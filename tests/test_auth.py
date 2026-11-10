import json
import subprocess
import time

import pytest

from azure_iam.auth import AzureCliAuth, ClientSecretAuth, resolve_auth, token_claims
from azure_iam.errors import AuthError
from conftest import make_token


def test_defaults_to_the_azure_cli_when_no_credentials_are_given():
    auth = resolve_auth(env={})
    assert isinstance(auth, AzureCliAuth)
    assert auth.tenant_id is None


def test_a_tenant_alone_still_uses_the_azure_cli():
    auth = resolve_auth(env={"AZURE_TENANT_ID": "t"})
    assert isinstance(auth, AzureCliAuth)
    assert auth.tenant_id == "t"


def test_complete_environment_credentials_use_the_app_registration():
    auth = resolve_auth(env={"AZURE_TENANT_ID": "t", "AZURE_CLIENT_ID": "c", "AZURE_CLIENT_SECRET": "s"})
    assert isinstance(auth, ClientSecretAuth)
    assert (auth.tenant_id, auth.client_id) == ("t", "c")


def test_legacy_environment_names_still_work():
    auth = resolve_auth(env={"TENANT_ID": "t", "CLIENT_ID": "c", "CLIENT_SECRET": "s"})
    assert isinstance(auth, ClientSecretAuth)
    assert (auth.tenant_id, auth.client_id) == ("t", "c")


def test_options_win_over_file_and_file_wins_over_environment(tmp_path):
    cred = tmp_path / "azure.env"
    cred.write_text("TENANT_ID=file-tenant\nCLIENT_ID=file-client\nCLIENT_SECRET=file-secret\n")
    env = {"AZURE_TENANT_ID": "env-tenant", "AZURE_CLIENT_ID": "env-client", "AZURE_CLIENT_SECRET": "env-secret"}
    auth = resolve_auth(client_id="flag-client", credential_file=str(cred), env=env)
    assert (auth.tenant_id, auth.client_id) == ("file-tenant", "flag-client")


def test_the_credential_file_does_not_leak_into_the_environment(tmp_path, monkeypatch):
    monkeypatch.delenv("CLIENT_SECRET", raising=False)
    cred = tmp_path / "azure.env"
    cred.write_text("TENANT_ID=t\nCLIENT_ID=c\nCLIENT_SECRET=s\n")
    resolve_auth(credential_file=str(cred), env={})
    import os

    assert "CLIENT_SECRET" not in os.environ


def test_partial_app_credentials_are_an_error_that_names_what_is_missing():
    with pytest.raises(AuthError, match="AZURE_CLIENT_SECRET"):
        resolve_auth(env={"AZURE_TENANT_ID": "t", "AZURE_CLIENT_ID": "c"})


def test_auth_cli_ignores_app_credentials():
    env = {"AZURE_TENANT_ID": "t", "AZURE_CLIENT_ID": "c", "AZURE_CLIENT_SECRET": "s"}
    assert isinstance(resolve_auth(mode="cli", env=env), AzureCliAuth)


def test_auth_app_without_credentials_is_an_error():
    with pytest.raises(AuthError):
        resolve_auth(mode="app", env={})


def test_a_missing_credential_file_is_an_error():
    with pytest.raises(AuthError, match="not found"):
        resolve_auth(credential_file="/no/such/file.env", env={})


def _completed(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def test_azure_cli_token_is_read_and_cached():
    calls = []
    token = make_token(scp="Directory.AccessAsUser.All User.Read", tid="tenant-1")

    def run(command, **kwargs):
        calls.append(command)
        return _completed(json.dumps({"accessToken": token, "expires_on": int(time.time()) + 3600}))

    auth = AzureCliAuth(tenant_id="tenant-1", run=run, which=lambda name: "/usr/bin/az")
    assert auth.get_token() == token
    assert auth.get_token() == token
    assert len(calls) == 1
    assert calls[0][:3] == ["/usr/bin/az", "account", "get-access-token"]
    assert calls[0][-2:] == ["--tenant", "tenant-1"]
    assert auth.granted_permissions() == ["Directory.AccessAsUser.All", "User.Read"]
    assert auth.token_tenant_id() == "tenant-1"


def test_azure_cli_token_is_fetched_again_when_close_to_expiry():
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        return _completed(json.dumps({"accessToken": "a.b.c", "expires_on": int(time.time()) + 10}))

    auth = AzureCliAuth(run=run, which=lambda name: "az")
    auth.get_token()
    auth.get_token()
    assert len(calls) == 2


def test_missing_azure_cli_explains_both_ways_to_sign_in():
    auth = AzureCliAuth(which=lambda name: None)
    with pytest.raises(AuthError, match="az login"):
        auth.get_token()


def test_azure_cli_failure_suggests_az_login():
    auth = AzureCliAuth(
        run=lambda command, **kwargs: _completed(stderr="ERROR: Please run 'az login'\nmore", returncode=1),
        which=lambda name: "az",
    )
    with pytest.raises(AuthError, match="Run `az login`") as raised:
        auth.get_token()
    assert "--allow-no-subscriptions" in str(raised.value)
    assert "Details: ERROR: Please run 'az login'" in str(raised.value)


def test_azure_cli_failure_for_a_named_tenant_suggests_signing_in_to_that_tenant():
    auth = AzureCliAuth(
        tenant_id="tenant-1",
        run=lambda command, **kwargs: _completed(stderr="ERROR: no such tenant", returncode=1),
        which=lambda name: "az",
    )
    with pytest.raises(AuthError, match="Run `az login --tenant tenant-1`"):
        auth.get_token()


def test_azure_cli_failure_passes_on_the_command_the_azure_cli_recommends():
    stderr = (
        "ERROR: AADSTS50076: You must use multi-factor authentication to access Microsoft Graph.\n"
        "Interactive authentication is needed. Please run:\n"
        "az login --scope https://graph.microsoft.com/.default\n"
    )
    auth = AzureCliAuth(run=lambda command, **kwargs: _completed(stderr=stderr, returncode=1), which=lambda name: "az")
    with pytest.raises(AuthError) as raised:
        auth.get_token()
    message = str(raised.value)
    assert "az login --scope https://graph.microsoft.com/.default" in message
    assert "Details: ERROR: AADSTS50076" in message


class _Response:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body

    def json(self):
        return self._body


class _Session:
    def __init__(self, response):
        self.response = response
        self.posts = []

    def post(self, url, data=None, timeout=None):
        self.posts.append((url, data))
        return self.response


def test_client_secret_is_sent_as_form_fields_so_special_characters_survive():
    session = _Session(_Response(200, {"access_token": make_token(roles=["Application.Read.All"]), "expires_in": 3600}))
    auth = ClientSecretAuth("tenant", "client", "s+e&c=r%t", session=session)
    auth.get_token()
    url, data = session.posts[0]
    assert url == "https://login.microsoftonline.com/tenant/oauth2/v2.0/token"
    assert data["client_secret"] == "s+e&c=r%t"
    assert data["grant_type"] == "client_credentials"
    assert auth.granted_permissions() == ["Application.Read.All"]


def test_client_secret_failure_reports_the_reason():
    session = _Session(_Response(401, {"error": "invalid_client", "error_description": "AADSTS7000215: bad secret"}))
    with pytest.raises(AuthError, match="AADSTS7000215"):
        ClientSecretAuth("t", "c", "s", session=session).get_token()


def test_token_claims_tolerates_garbage():
    assert token_claims("not-a-token") == {}
    assert token_claims(None) == {}
