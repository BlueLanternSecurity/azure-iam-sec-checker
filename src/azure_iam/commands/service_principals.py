"""Service principals and the Microsoft Graph application permissions they hold.

These checks report permissions that were *granted* (app role assignments on
the Microsoft Graph service principal). That covers app registrations in this
tenant and enterprise apps that live in another tenant.
"""

import importlib.resources
import json

import click

from azure_iam.commands.common import graph_command, is_on, list_flag
from azure_iam.errors import NotFoundError

GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
NEEDS = ("Application.Read.All",)


def load_risky_permissions():
    resource = importlib.resources.files("azure_iam") / "data" / "risky_permissions.json"
    with resource.open("r", encoding="utf-8") as handle:
        return json.load(handle)


class GrantIndex:
    """Everything needed to answer "who holds permission X", fetched once."""

    def __init__(self, client):
        graph = client.get_one(
            f"v1.0/servicePrincipals(appId='{GRAPH_APP_ID}')",
            params={"$select": "id,appRoles"},
        )
        self._app_roles = graph.get("appRoles") or []
        self._grants = client.get_all(f"v1.0/servicePrincipals(appId='{GRAPH_APP_ID}')/appRoleAssignedTo")
        principals = client.get_all(
            "v1.0/servicePrincipals",
            params={
                "$select": "id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,accountEnabled",
                "$top": "999",
            },
        )
        self._principals = {p["id"]: p for p in principals}
        self._home_tenant = client.auth.token_tenant_id()

    def resolve(self, permission):
        """Return {app role id: permission name} for a name such as Directory.Read.All."""
        wanted = permission.strip().lower()
        return {
            role["id"]: role.get("value") or permission
            for role in self._app_roles
            if wanted in ((role.get("value") or "").lower(), (role.get("displayName") or "").lower())
        }

    def holders(self, permission):
        """Service principals granted the permission, or None if it is unknown."""
        role_ids = self.resolve(permission)
        if not role_ids:
            return None
        results = []
        for grant in self._grants:
            if grant.get("appRoleId") not in role_ids:
                continue
            if grant.get("principalType") not in (None, "ServicePrincipal"):
                continue
            principal = self._principals.get(grant.get("principalId"), {})
            owner = principal.get("appOwnerOrganizationId")
            results.append(
                {
                    "app_name": principal.get("displayName") or grant.get("principalDisplayName"),
                    "app_id": principal.get("appId"),
                    "service_principal_id": grant.get("principalId"),
                    "service_principal_type": principal.get("servicePrincipalType"),
                    "account_enabled": principal.get("accountEnabled"),
                    "owner_tenant_id": owner,
                    "external_owner": (owner != self._home_tenant) if owner and self._home_tenant else None,
                    "permission": role_ids[grant["appRoleId"]],
                    "granted_on": grant.get("createdDateTime"),
                }
            )
        results.sort(key=lambda r: ((r["app_name"] or "").lower(), r["service_principal_id"] or ""))
        return results


@click.option("--permission", required=True, help="Application permission to look for, e.g. Directory.Read.All.")
@graph_command(
    "find-service-principals-with-permission",
    help="Find service principals that were granted a Microsoft Graph application permission.",
    needs=NEEDS,
)
def find_service_principals_with_permission(session, permission):
    holders = GrantIndex(session.client).holders(permission)
    if holders is None:
        raise NotFoundError(
            f"'{permission}' is not a Microsoft Graph application permission. "
            "Use the permission value, e.g. Directory.Read.All."
        )
    return holders


@list_flag("--list-permissions", help="Print the bundled list of risky permissions and exit. Needs no sign-in.")
@graph_command(
    "find-risky-service-principals",
    help="Find service principals that were granted a high-risk Microsoft Graph application permission.",
    needs=NEEDS,
)
def find_risky_service_principals(session, list_permissions):
    risky = load_risky_permissions()
    if is_on(list_permissions):
        return risky
    index = GrantIndex(session.client)
    results = []
    for entry in risky:
        holders = index.holders(entry["permission"])
        if holders is None:
            click.echo(
                f"Warning: bundled permission {entry['permission']} was not found on Microsoft Graph; skipped.",
                err=True,
            )
            continue
        for holder in holders:
            results.append({**holder, "risk": entry["risk"], "reason": entry["reason"]})
    return results
