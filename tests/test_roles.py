from azure_iam.commands.roles import ActionMatcher, roles_allowing
from conftest import FakeGraph

ROLE_DEFS = "v1.0/roleManagement/directory/roleDefinitions"
ASSIGNMENTS = "v1.0/roleManagement/directory/roleAssignments"
ACTIONS = "beta/roleManagement/directory/resourceNamespaces/microsoft.directory/resourceActions"

RESET = "microsoft.directory/users/password/update"
CREDS = "microsoft.directory/applications/credentials/update"

ROLES = [
    {
        "id": "role-helpdesk",
        "displayName": "Helpdesk Administrator",
        "isBuiltIn": True,
        "isEnabled": True,
        "rolePermissions": [{"allowedResourceActions": [RESET, "microsoft.directory/users/basic/read"]}],
    },
    {
        "id": "role-appadmin",
        "displayName": "Application Administrator",
        "isBuiltIn": True,
        "isEnabled": True,
        "rolePermissions": [{"allowedResourceActions": [CREDS]}],
    },
    {
        "id": "role-reader",
        "displayName": "Directory Readers",
        "isBuiltIn": True,
        "isEnabled": True,
        "rolePermissions": [{"allowedResourceActions": ["microsoft.directory/users/basic/read"]}],
    },
    {
        "id": "role-owner-only",
        "displayName": "Conditional Only",
        "isBuiltIn": False,
        "isEnabled": True,
        "rolePermissions": [{"allowedResourceActions": [CREDS], "condition": "$ResourceIsSelf"}],
    },
]

ALICE = {"@odata.type": "#microsoft.graph.user", "id": "u-alice", "displayName": "Alice", "userPrincipalName": "alice@example.com"}
BOT = {"@odata.type": "#microsoft.graph.servicePrincipal", "id": "sp-bot", "displayName": "Deploy Bot"}


def assignments(path, params):
    by_role = {
        "role-helpdesk": [{"principalId": "u-alice", "directoryScopeId": "/", "principal": ALICE}],
        "role-appadmin": [
            {"principalId": "u-alice", "directoryScopeId": "/", "principal": ALICE},
            {"principalId": "sp-bot", "directoryScopeId": "/", "principal": BOT},
        ],
    }
    for role_id, rows in by_role.items():
        if role_id in params["$filter"]:
            return rows
    return []


def role_definitions(path, params):
    if params and "$filter" in params:
        return [r for r in ROLES if f"'{r['displayName']}'" in params["$filter"]]
    return ROLES


def tenant():
    return FakeGraph(
        {
            ROLE_DEFS: role_definitions,
            ASSIGNMENTS: assignments,
            ACTIONS: [{"name": RESET}, {"name": CREDS}],
        }
    )


def test_exact_match_is_case_insensitive():
    assert ActionMatcher([RESET]).match(RESET.upper()) == RESET


def test_wildcard_in_the_searched_action():
    assert ActionMatcher(["microsoft.directory/users/*"]).match(RESET) == "microsoft.directory/users/*"


def test_wildcard_in_the_role_action():
    assert ActionMatcher([RESET]).match("microsoft.directory/users/*") == RESET


def test_a_prefix_is_not_a_match():
    assert ActionMatcher(["microsoft.directory/users"]).match(RESET) is None
    assert ActionMatcher([RESET]).match("microsoft.directory/users/password") is None


def test_dots_are_literal():
    assert ActionMatcher(["microsoftXdirectory/users/password/update"]).match(RESET) is None


def test_conditional_permissions_are_skipped():
    names = [r["name"] for r in roles_allowing(ROLES, [CREDS])]
    assert names == ["Application Administrator"]


def test_find_entra_roles_with_action(run_json):
    results = run_json(["find-entra-roles-with-action", "--action", RESET], tenant())
    assert [r["name"] for r in results] == ["Helpdesk Administrator"]
    assert results[0]["checkedAction"] == RESET


def test_find_role_members(run_json):
    results = run_json(["find-role-members", "--role", "Application Administrator"], tenant())
    assert results == [
        {
            "principalID": "u-alice",
            "displayName": "Alice",
            "userPrincipalName": "alice@example.com",
            "role": "Application Administrator",
            "principalType": "#microsoft.graph.user",
            "directoryScopeId": "/",
        },
        {
            "principalID": "sp-bot",
            "displayName": "Deploy Bot",
            "userPrincipalName": None,
            "role": "Application Administrator",
            "principalType": "#microsoft.graph.servicePrincipal",
            "directoryScopeId": "/",
        },
    ]


def test_an_unknown_role_is_an_error(run):
    code, out, err = run(["find-role-members", "--role", "No Such Role"], tenant())
    assert code == 1
    assert out == ""
    assert "No Such Role" in err


def test_a_role_name_with_a_quote_is_escaped(run):
    graph = tenant()
    run(["find-role-members", "--role", "O'Brien's role"], graph)
    assert graph.calls[0][1]["$filter"] == "displayName eq 'O''Brien''s role'"


def test_privileged_users_are_merged_across_roles(run_json):
    results = run_json(["find-privileged-users"], tenant())
    by_id = {r["principalID"]: r for r in results}
    assert set(by_id) == {"u-alice", "sp-bot"}
    assert by_id["u-alice"]["roles"] == ["Helpdesk Administrator", "Application Administrator"]
    assert by_id["sp-bot"]["roles"] == ["Application Administrator"]
    assert "role" not in by_id["u-alice"]


def test_list_privileged_actions_and_roles(run_json):
    assert run_json(["find-privileged-users", "--list-privileged-actions"], tenant()) == [RESET, CREDS]
    assert run_json(["find-privileged-users", "--list_privileged_roles", "true"], tenant()) == [
        "Helpdesk Administrator",
        "Application Administrator",
    ]
