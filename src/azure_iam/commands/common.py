"""Shared plumbing for commands: sign-in options, error handling and output."""

import functools
import json

import click

from azure_iam.auth import resolve_auth
from azure_iam.errors import AzureIamError, GraphError
from azure_iam.graph import GraphClient

AUTH_KEYS = ("azure_tenant_id", "azure_client_id", "azure_client_secret", "credential_file", "auth")


def common_options(f):
    """Sign-in options. Accepted before or after the command name."""
    options = [
        click.option(
            "--azure-tenant-id",
            default=None,
            help="Tenant ID. Optional with `az login`; required with an app registration.",
        ),
        click.option("--azure-client-id", default=None, help="Client ID of an app registration."),
        click.option(
            "--azure-client-secret",
            default=None,
            help="Client secret of the app registration. Prefer AZURE_CLIENT_SECRET or "
            "--credential-file so the secret stays out of shell history.",
        ),
        click.option(
            "--credential-file",
            default=None,
            type=click.Path(dir_okay=False),
            help="Dotenv file with AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET.",
        ),
        click.option(
            "--auth",
            default=None,
            type=click.Choice(["auto", "cli", "app"]),
            help="How to sign in. auto (default): app registration if credentials are "
            "provided, otherwise your `az login` session.",
        ),
    ]
    for option in reversed(options):
        f = option(f)
    return f


def list_flag(name, help):
    """A switch that also tolerates a trailing value, e.g. `--list-permissions true`."""
    return click.option(name, is_flag=False, flag_value="true", default=None, metavar="", help=help)


def is_on(value):
    """Whether a list switch was given, allowing an explicit `false`."""
    return value is not None and str(value).strip().lower() not in ("", "false", "0", "no")


def build_client(settings):
    auth = resolve_auth(
        tenant_id=settings.get("azure_tenant_id"),
        client_id=settings.get("azure_client_id"),
        client_secret=settings.get("azure_client_secret"),
        credential_file=settings.get("credential_file"),
        mode=settings.get("auth"),
    )
    return GraphClient(auth)


class Session:
    """Creates the Graph client on first use, so commands that only print
    bundled data need no credentials."""

    def __init__(self, settings):
        self._settings = settings
        self._client = None

    @property
    def client(self):
        if self._client is None:
            self._client = build_client(self._settings)
        return self._client

    def permission_hint(self, needs):
        if self._client is None:
            return ""
        auth = self._client.auth
        held = auth.granted_permissions()
        hint = f"\nThis command needs Microsoft Graph permission(s): {', '.join(needs)}."
        hint += f"\nSigned in with: {auth.name}."
        if held:
            hint += f" The token carries: {', '.join(held)}."
        if auth.name.startswith("Azure CLI"):
            hint += (
                "\nWith an Azure CLI sign-in this usually means your account lacks a "
                "directory role that can read this data, such as Global Reader. An app "
                "registration with the permission(s) above also works (see the README)."
            )
        return hint


def graph_command(name, help, needs):
    """Declare a command. The function receives a Session followed by its own
    options and returns the data to print as JSON."""

    def decorator(fn):
        @click.command(name, help=help)
        @common_options
        @click.pass_context
        @functools.wraps(fn)
        def wrapper(ctx, **kwargs):
            settings = dict(ctx.obj or {})
            for key in AUTH_KEYS:
                value = kwargs.pop(key, None)
                if value is not None:
                    settings[key] = value
            session = Session(settings)
            try:
                result = fn(session, **kwargs)
            except GraphError as exc:
                message = str(exc)
                if exc.status == 403:
                    message += session.permission_hint(needs)
                raise click.ClickException(message) from exc
            except AzureIamError as exc:
                raise click.ClickException(str(exc)) from exc
            click.echo(json.dumps(result, indent=2))

        return wrapper

    return decorator
