"""Obtaining Microsoft Graph tokens.

Two ways to sign in:

* Azure CLI: reuse the session created by ``az login``. This is the default.
* App registration: a tenant ID, client ID and client secret.
"""

import base64
import json
import os
import shutil
import subprocess
import time

import requests
from dotenv import dotenv_values

from azure_iam.errors import AuthError

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
LOGIN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
EXPIRY_MARGIN_SECONDS = 300

# Each setting: the preferred environment variable, then the legacy name.
ENV_NAMES = {
    "tenant_id": ("AZURE_TENANT_ID", "TENANT_ID"),
    "client_id": ("AZURE_CLIENT_ID", "CLIENT_ID"),
    "client_secret": ("AZURE_CLIENT_SECRET", "CLIENT_SECRET"),
}


def token_claims(token):
    """Decode a token's claims without verifying it. For diagnostics only."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except (IndexError, ValueError, AttributeError):
        return {}


class _CachedToken:
    """Shared caching: reuse a token until shortly before it expires."""

    name = ""

    def __init__(self):
        self._token = None
        self._expires_at = None

    def get_token(self, force_refresh=False):
        expired = (
            self._expires_at is not None
            and time.time() >= self._expires_at - EXPIRY_MARGIN_SECONDS
        )
        if force_refresh or self._token is None or expired:
            self._token, self._expires_at = self._fetch()
        return self._token

    def granted_permissions(self):
        """Permissions carried by the current token, or an empty list."""
        claims = token_claims(self._token) if self._token else {}
        if claims.get("roles"):
            return sorted(claims["roles"])
        return sorted(claims.get("scp", "").split())

    def token_tenant_id(self):
        claims = token_claims(self._token) if self._token else {}
        return claims.get("tid")

    def _fetch(self):
        raise NotImplementedError


class ClientSecretAuth(_CachedToken):
    name = "app registration"

    def __init__(self, tenant_id, client_id, client_secret, session=None):
        super().__init__()
        self.tenant_id = tenant_id
        self.client_id = client_id
        self._client_secret = client_secret
        self._session = session or requests.Session()

    def _fetch(self):
        try:
            response = self._session.post(
                LOGIN_URL.format(tenant=self.tenant_id),
                data={
                    "client_id": self.client_id,
                    "client_secret": self._client_secret,
                    "grant_type": "client_credentials",
                    "scope": GRAPH_SCOPE,
                },
                timeout=30,
            )
        except requests.RequestException as exc:
            raise AuthError(f"Could not reach the Microsoft sign-in service: {exc}") from exc
        try:
            body = response.json()
        except ValueError:
            body = {}
        if response.status_code != 200 or "access_token" not in body:
            detail = body.get("error_description") or body.get("error") or f"HTTP {response.status_code}"
            raise AuthError(
                "Sign-in with the app registration failed. Check the tenant ID, "
                f"client ID and client secret. Details: {detail}"
            )
        expires_at = time.time() + int(body.get("expires_in", 3600))
        return body["access_token"], expires_at


class AzureCliAuth(_CachedToken):
    name = "Azure CLI sign-in"

    def __init__(self, tenant_id=None, run=subprocess.run, which=shutil.which):
        super().__init__()
        self.tenant_id = tenant_id
        self._run = run
        self._which = which

    def _fetch(self):
        az = self._which("az")
        if not az:
            raise AuthError(
                "The Azure CLI was not found. Install it and run `az login`, or "
                "provide app registration credentials (see the README)."
            )
        command = [az, "account", "get-access-token", "--resource-type", "ms-graph", "--output", "json"]
        if self.tenant_id:
            command += ["--tenant", self.tenant_id]
        try:
            result = self._run(command, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError) as exc:
            raise AuthError(f"Could not run the Azure CLI: {exc}") from exc
        if result.returncode != 0:
            raise AuthError(_cli_failure_message(result.stderr, self.tenant_id))
        try:
            body = json.loads(result.stdout)
            token = body["accessToken"]
        except (ValueError, KeyError, TypeError) as exc:
            raise AuthError("The Azure CLI returned an unexpected response.") from exc
        expires_at = body.get("expires_on")
        try:
            expires_at = float(expires_at) if expires_at is not None else None
        except (TypeError, ValueError):
            expires_at = None
        return token, expires_at


def _cli_failure_message(stderr, tenant_id=None):
    """Explain a failed ``az account get-access-token`` and how to fix it."""
    lines = [line.strip() for line in (stderr or "").splitlines() if line.strip()]
    message = "The Azure CLI could not provide a Microsoft Graph token. "
    # When a session has to be renewed for Microsoft Graph (expired, or MFA is
    # required), the Azure CLI prints the exact command; a plain `az login`
    # is not always enough.
    suggested = next((line for line in lines if line.startswith("az login")), None)
    if suggested:
        message += f"Sign in again and retry:\n  {suggested}"
    else:
        command = f"az login --tenant {tenant_id}" if tenant_id else "az login"
        message += (
            f"Run `{command}` and try again. If your account has no Azure "
            "subscription, add --allow-no-subscriptions."
        )
    if lines:
        message += f"\nDetails: {lines[0]}"
    return message


def _first_set(mapping, names):
    for name in names:
        value = mapping.get(name)
        if value:
            return value
    return None


def resolve_auth(
    tenant_id=None,
    client_id=None,
    client_secret=None,
    credential_file=None,
    mode=None,
    env=None,
):
    """Pick how to sign in.

    Explicit options win over the credential file, which wins over environment
    variables. With a complete set of app credentials the app registration is
    used; with none, the Azure CLI session is used. ``mode`` may force "cli" or
    "app"; "auto" or None chooses as described.
    """
    env = os.environ if env is None else env
    mode = mode or "auto"

    file_values = {}
    if credential_file:
        if not os.path.isfile(credential_file):
            raise AuthError(f"Credential file not found: {credential_file}")
        file_values = dotenv_values(credential_file)

    given = {"tenant_id": tenant_id, "client_id": client_id, "client_secret": client_secret}
    settings = {}
    for key, names in ENV_NAMES.items():
        settings[key] = given[key] or _first_set(file_values, names) or _first_set(env, names)

    if mode == "cli":
        return AzureCliAuth(tenant_id=settings["tenant_id"])

    has_id, has_secret = bool(settings["client_id"]), bool(settings["client_secret"])
    if mode == "app" or has_id or has_secret:
        missing = [
            ENV_NAMES[key][0] for key in ("tenant_id", "client_id", "client_secret") if not settings[key]
        ]
        if missing:
            raise AuthError(
                "App registration sign-in needs a tenant ID, client ID and client secret. "
                f"Missing: {', '.join(missing)}. To use your `az login` session instead, "
                "unset the others or pass --auth cli."
            )
        return ClientSecretAuth(settings["tenant_id"], settings["client_id"], settings["client_secret"])

    return AzureCliAuth(tenant_id=settings["tenant_id"])
