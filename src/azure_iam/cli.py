import click

from azure_iam.commands.common import AUTH_KEYS, common_options
from azure_iam.commands.conditional_access import evaluate_conditional_access_policies
from azure_iam.commands.roles import find_entra_roles_with_action, find_privileged_users, find_role_members
from azure_iam.commands.service_principals import (
    find_risky_service_principals,
    find_service_principals_with_permission,
)


def _dashes(token):
    # Accept --azure_tenant_id as well as --azure-tenant-id.
    return token.replace("_", "-")


@click.group(context_settings={"token_normalize_func": _dashes, "help_option_names": ["-h", "--help"]})
@click.version_option(package_name="azure-iam-sec-checker")
@common_options
@click.pass_context
def main(ctx, **kwargs):
    """Read-only security checks for Microsoft Entra ID.

    Signs in with your `az login` session by default. Results are printed as
    JSON on stdout; errors go to stderr with a non-zero exit code.
    """
    ctx.obj = {key: kwargs[key] for key in AUTH_KEYS if kwargs.get(key) is not None}


main.add_command(find_risky_service_principals)
main.add_command(find_service_principals_with_permission)
main.add_command(find_role_members)
main.add_command(find_entra_roles_with_action)
main.add_command(find_privileged_users)
main.add_command(evaluate_conditional_access_policies)


if __name__ == "__main__":
    main()
