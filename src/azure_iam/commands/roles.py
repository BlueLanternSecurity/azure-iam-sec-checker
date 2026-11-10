"""Entra directory roles: who is in them and what they allow."""

import re

import click

from azure_iam.commands.common import graph_command, is_on, list_flag
from azure_iam.errors import NotFoundError

NEEDS = ("RoleManagement.Read.Directory", "Directory.Read.All")
ROLE_DEFINITIONS = "v1.0/roleManagement/directory/roleDefinitions"
ROLE_ASSIGNMENTS = "v1.0/roleManagement/directory/roleAssignments"
PRIVILEGED_ACTIONS = "beta/roleManagement/directory/resourceNamespaces/microsoft.directory/resourceActions"


def _odata_quote(value):
    return value.replace("'", "''")


def _wildcard(pattern):
    return re.compile("".join(".*" if ch == "*" else re.escape(ch) for ch in pattern), re.IGNORECASE)


class ActionMatcher:
    """Matches role actions against a set of actions. `*` is a wildcard on either side."""

    def __init__(self, actions):
        self._exact = {a.lower(): a for a in actions if "*" not in a}
        self._patterns = [(a, _wildcard(a)) for a in actions if "*" in a]
        self._plain = [a for a in actions if "*" not in a]

    def match(self, allowed_action):
        """Return the first of our actions that overlaps with a role's allowed action."""
        hit = self._exact.get(allowed_action.lower())
        if hit:
            return hit
        for action, pattern in self._patterns:
            if pattern.fullmatch(allowed_action):
                return action
        if "*" in allowed_action:
            pattern = _wildcard(allowed_action)
            for action in self._plain:
                if pattern.fullmatch(action):
                    return action
        return None


def roles_allowing(role_definitions, actions):
    """Roles with an unconditional permission that allows any of the actions."""
    matcher = ActionMatcher(actions)
    found = []
    for role in role_definitions:
        hit = None
        for permission in role.get("rolePermissions") or []:
            if permission.get("condition"):
                continue
            for allowed in permission.get("allowedResourceActions") or []:
                hit = matcher.match(allowed)
                if hit:
                    break
            if hit:
                break
        if hit:
            found.append(
                {
                    "id": role.get("id"),
                    "name": role.get("displayName"),
                    "description": role.get("description"),
                    "isBuiltIn": role.get("isBuiltIn"),
                    "isEnabled": role.get("isEnabled"),
                    "resourceScopes": role.get("resourceScopes"),
                    "checkedAction": hit,
                }
            )
    return found


def find_role(client, name):
    matches = client.get_all(ROLE_DEFINITIONS, params={"$filter": f"displayName eq '{_odata_quote(name)}'"})
    if not matches:
        raise NotFoundError(f"No Entra role named '{name}' was found.")
    return matches[0]


def role_members(client, role_id, role_name):
    assignments = client.get_all(
        ROLE_ASSIGNMENTS,
        params={"$filter": f"roleDefinitionId eq '{_odata_quote(role_id)}'", "$expand": "principal"},
    )
    members = []
    for assignment in assignments:
        principal = assignment.get("principal") or {}
        members.append(
            {
                "principalID": principal.get("id") or assignment.get("principalId"),
                "displayName": principal.get("displayName"),
                "userPrincipalName": principal.get("userPrincipalName"),
                "role": role_name,
                "principalType": principal.get("@odata.type"),
                "directoryScopeId": assignment.get("directoryScopeId"),
            }
        )
    return members


@click.option("--role", required=True, help="Display name of the role, e.g. \"Global Administrator\".")
@graph_command("find-role-members", help="List the principals assigned to an Entra role.", needs=NEEDS)
def find_role_members(session, role):
    definition = find_role(session.client, role)
    return role_members(session.client, definition["id"], definition.get("displayName") or role)


@click.option(
    "--action",
    required=True,
    help="Directory action to search for, e.g. microsoft.directory/applications/credentials/update. "
    "`*` is a wildcard.",
)
@graph_command("find-entra-roles-with-action", help="Find the Entra roles that allow a directory action.", needs=NEEDS)
def find_entra_roles_with_action(session, action):
    return roles_allowing(session.client.get_all(ROLE_DEFINITIONS), [action])


@list_flag("--list-privileged-roles", help="Print the roles that contain a privileged action and exit.")
@list_flag("--list-privileged-actions", help="Print the actions Microsoft marks as privileged and exit.")
@graph_command(
    "find-privileged-users",
    help="Find principals assigned a role that contains an action Microsoft marks as privileged.",
    needs=NEEDS,
)
def find_privileged_users(session, list_privileged_actions, list_privileged_roles):
    client = session.client
    actions = [
        item["name"]
        for item in client.get_all(PRIVILEGED_ACTIONS, params={"$filter": "isPrivileged eq true"})
        if item.get("name")
    ]
    if is_on(list_privileged_actions):
        return actions
    roles = roles_allowing(client.get_all(ROLE_DEFINITIONS), actions)
    if is_on(list_privileged_roles):
        return [role["name"] for role in roles]

    principals = {}
    for role in roles:
        for member in role_members(client, role["id"], role["name"]):
            entry = principals.get(member["principalID"])
            if entry is None:
                entry = {key: value for key, value in member.items() if key not in ("role", "directoryScopeId")}
                entry["roles"] = []
                principals[member["principalID"]] = entry
            if member["role"] not in entry["roles"]:
                entry["roles"].append(member["role"])
    return list(principals.values())
