import json

from azure_iam.commands.service_principals import load_risky_permissions
from azure_iam.errors import GraphError
from conftest import HOME_TENANT, OTHER_TENANT, FakeAuth, FakeGraph

GRAPH_SP = "v1.0/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')"

APP_ROLES = [
    {"id": "role-dir-read", "value": "Directory.Read.All", "displayName": "Read directory data"},
    {"id": "role-dir-write", "value": "Directory.ReadWrite.All", "displayName": "Read and write directory data"},
    {"id": "role-rm-write", "value": "RoleManagement.ReadWrite.Directory", "displayName": "Read and write all directory RBAC settings"},
    {"id": "role-app-write", "value": "Application.ReadWrite.All", "displayName": "Read and write all applications"},
]

PRINCIPALS = [
    {
        "id": "sp-local",
        "appId": "app-local",
        "displayName": "Payroll Sync",
        "servicePrincipalType": "Application",
        "appOwnerOrganizationId": HOME_TENANT,
        "accountEnabled": True,
    },
    {
        "id": "sp-vendor",
        "appId": "app-vendor",
        "displayName": "Vendor Backup",
        "servicePrincipalType": "Application",
        "appOwnerOrganizationId": OTHER_TENANT,
        "accountEnabled": True,
    },
    {
        "id": "sp-requested-only",
        "appId": "app-requested",
        "displayName": "Never Consented",
        "servicePrincipalType": "Application",
        "appOwnerOrganizationId": HOME_TENANT,
        "accountEnabled": True,
    },
]

GRANTS = [
    {"principalId": "sp-local", "principalType": "ServicePrincipal", "principalDisplayName": "Payroll Sync", "appRoleId": "role-dir-read", "createdDateTime": "2025-01-01T00:00:00Z"},
    {"principalId": "sp-vendor", "principalType": "ServicePrincipal", "principalDisplayName": "Vendor Backup", "appRoleId": "role-dir-write", "createdDateTime": "2025-02-02T00:00:00Z"},
    {"principalId": "sp-vendor", "principalType": "ServicePrincipal", "principalDisplayName": "Vendor Backup", "appRoleId": "role-rm-write", "createdDateTime": "2025-02-03T00:00:00Z"},
]


def tenant(grants=GRANTS, app_roles=APP_ROLES, principals=PRINCIPALS, auth=None):
    return FakeGraph(
        {
            GRAPH_SP + "/appRoleAssignedTo": grants,
            GRAPH_SP: {"id": "graph-sp", "appRoles": app_roles},
            "v1.0/servicePrincipals": principals,
        },
        auth=auth,
    )


def test_reports_who_was_granted_a_permission(run_json):
    results = run_json(["find-service-principals-with-permission", "--permission", "Directory.Read.All"], tenant())
    assert len(results) == 1
    assert results[0] == {
        "app_name": "Payroll Sync",
        "app_id": "app-local",
        "service_principal_id": "sp-local",
        "service_principal_type": "Application",
        "account_enabled": True,
        "owner_tenant_id": HOME_TENANT,
        "external_owner": False,
        "permission": "Directory.Read.All",
        "granted_on": "2025-01-01T00:00:00Z",
    }


def test_finds_an_enterprise_app_owned_by_another_tenant(run_json):
    results = run_json(["find-service-principals-with-permission", "--permission", "Directory.ReadWrite.All"], tenant())
    assert [r["app_name"] for r in results] == ["Vendor Backup"]
    assert results[0]["external_owner"] is True
    assert results[0]["owner_tenant_id"] == OTHER_TENANT


def test_an_app_that_only_requested_a_permission_is_not_reported(run_json):
    graph = tenant()
    results = run_json(["find-service-principals-with-permission", "--permission", "Application.ReadWrite.All"], graph)
    assert results == []
    assert not any(path.startswith("v1.0/applications") for path, _ in graph.calls)


def test_permission_name_is_case_insensitive_and_accepts_the_display_name(run_json):
    by_value = run_json(["find-service-principals-with-permission", "--permission", "directory.read.all"], tenant())
    by_name = run_json(["find-service-principals-with-permission", "--permission", "Read directory data"], tenant())
    assert by_value == by_name and len(by_value) == 1


def test_an_unknown_permission_is_an_error_not_an_empty_result(run):
    code, out, err = run(["find-service-principals-with-permission", "--permission", "Not.A.Permission"], tenant())
    assert code == 1
    assert out == ""
    assert "Not.A.Permission" in err


def test_risky_check_attaches_risk_and_reason(run_json):
    results = run_json(["find-risky-service-principals"], tenant())
    assert {(r["app_name"], r["permission"]) for r in results} == {
        ("Vendor Backup", "Directory.ReadWrite.All"),
        ("Vendor Backup", "RoleManagement.ReadWrite.Directory"),
    }
    for r in results:
        assert r["risk"] and r["reason"]


def test_risky_check_fetches_each_collection_once(run_json):
    graph = tenant()
    run_json(["find-risky-service-principals"], graph)
    assert len(graph.calls) == 3


def test_risky_check_survives_a_bundled_permission_missing_from_graph(run):
    # Only one of the bundled permissions exists in this fake tenant.
    graph = tenant(app_roles=[APP_ROLES[1]])
    code, out, err = run(["find-risky-service-principals"], graph)
    assert code == 0
    assert [r["permission"] for r in json.loads(out)] == ["Directory.ReadWrite.All"]
    assert "Warning" in err and "RoleManagement.ReadWrite.Directory" in err


def test_risky_check_with_no_grants_returns_an_empty_list(run_json):
    assert run_json(["find-risky-service-principals"], tenant(grants=[])) == []


def test_list_permissions_needs_no_sign_in(run_json):
    listed = run_json(["find-risky-service-principals", "--list-permissions"], graph=None)
    assert listed == load_risky_permissions()
    assert {"permission", "risk", "reason"} <= set(listed[0])


def test_list_permissions_accepts_the_old_spelling_with_a_value(run_json):
    listed = run_json(["find-risky-service-principals", "--list_permissions", "True"], graph=None)
    assert listed == load_risky_permissions()


def test_the_bundled_list_is_well_formed():
    entries = load_risky_permissions()
    names = [entry["permission"] for entry in entries]
    assert len(names) == len(set(names)), "a permission is listed twice"
    for entry in entries:
        assert set(entry) == {"permission", "risk", "reason"}
        assert all(isinstance(value, str) and value.strip() for value in entry.values())


def test_forbidden_explains_which_permission_is_needed(run):
    graph = FakeGraph(
        {"v1.0/servicePrincipals": GraphError("Microsoft Graph request failed with HTTP 403", status=403)},
        auth=FakeAuth(scopes="User.Read"),
    )
    code, out, err = run(["find-risky-service-principals"], graph)
    assert code == 1
    assert out == ""
    assert "Application.Read.All" in err
    assert "User.Read" in err
    assert "Azure CLI sign-in" in err


def test_list_permissions_false_runs_the_check(run_json):
    results = run_json(["find-risky-service-principals", "--list-permissions", "false"], tenant())
    assert {r["app_name"] for r in results} == {"Vendor Backup"}
