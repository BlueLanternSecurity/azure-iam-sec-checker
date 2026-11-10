import pytest

from azure_iam.commands import conditional_access as ca
from azure_iam.errors import GraphError
from conftest import FakeGraph

POLICIES = "v1.0/identity/conditionalAccess/policies"


def policy(name="P", state="enabled", include_users=("All",), exclude_users=(), include_roles=(),
           apps=("All",), controls=("mfa",), client_apps=(), sign_in_risk=(), user_risk=(), session=None):
    return {
        "displayName": name,
        "state": state,
        "conditions": {
            "users": {
                "includeUsers": list(include_users),
                "excludeUsers": list(exclude_users),
                "includeRoles": list(include_roles),
            },
            "applications": {"includeApplications": list(apps)},
            "clientAppTypes": list(client_apps),
            "signInRiskLevels": list(sign_in_risk),
            "userRiskLevels": list(user_risk),
        },
        "grantControls": {"builtInControls": list(controls)} if controls else None,
        "sessionControls": session,
    }


WELL_CONFIGURED = [
    policy("MFA for everyone"),
    policy("Block legacy auth", controls=("block",), client_apps=("exchangeActiveSync", "other")),
    policy("High sign-in risk", sign_in_risk=("high",)),
    policy("High user risk", user_risk=("high",), controls=("passwordChange",)),
    policy(
        "No persistent browser",
        controls=("mfa", "compliantDevice"),
        session={"persistentBrowser": {"isEnabled": True, "mode": "never"}},
    ),
]

ALL_CHECKS = ca.HIGH_CHECKS + ca.MEDIUM_CHECKS + ca.INFO_CHECKS


@pytest.mark.parametrize("check", ALL_CHECKS, ids=lambda c: c.__name__)
@pytest.mark.parametrize("policies", [[], WELL_CONFIGURED], ids=["empty tenant", "well configured tenant"])
def test_every_check_returns_a_list(check, policies):
    assert isinstance(check(policies), list)


def test_user_exclusions_returns_a_list():
    assert ca.check_user_exclusions([]) == []
    assert ca.check_user_exclusions(WELL_CONFIGURED) == []


def test_an_empty_tenant_fails_the_tenant_wide_checks():
    checks = {f["check"] for f in ca.evaluate([])}
    assert checks == {
        "Admin MFA Coverage Gap",
        "Legacy Authentication Not Blocked",
        "No High User Risk Policy",
        "No Universal MFA Policy",
        "Guest MFA Not Enforced",
        "No High Sign-In Risk Policy",
        "Persistent Browser Sessions Allowed",
    }


def test_a_well_configured_tenant_has_no_high_or_medium_findings():
    assert ca.evaluate(WELL_CONFIGURED, "medium") == []


def test_threshold_limits_the_severities_reported():
    assert {f["severity"] for f in ca.evaluate([], "high")} == {"HIGH"}
    assert {f["severity"] for f in ca.evaluate([], "medium")} == {"HIGH", "MEDIUM"}
    assert {f["severity"] for f in ca.evaluate([], "info")} == {"HIGH", "MEDIUM", "INFO"}
    assert ca.evaluate([]) == ca.evaluate([], "info")


def test_admin_mfa_names_the_uncovered_roles():
    global_admin = "62e90394-69f5-4237-9190-012177145e10"
    findings = ca.check_admin_mfa([policy(include_users=(), include_roles=(global_admin,))])
    assert len(findings) == 1
    assert "Global Administrator" not in findings[0]["detail"]
    assert "Security Administrator" in findings[0]["detail"]


def test_disabled_and_report_only_policies_do_not_count():
    off = [policy("off", state="disabled"), policy("report", state="enabledForReportingButNotEnforced")]
    assert ca.check_all_user_mfa(off) != []
    assert [f["policy"] for f in ca.check_disabled_policies(off)] == ["off"]
    assert [f["policy"] for f in ca.check_report_only(off)] == ["report"]


def test_universal_mfa_does_not_count_with_user_exclusions():
    assert ca.check_all_user_mfa([policy(exclude_users=("u-1",))]) != []


def test_unrestricted_grant_and_incomplete_conditions():
    assert [f["policy"] for f in ca.check_no_grant_controls([policy("open", controls=())])] == ["open"]
    assert [f["policy"] for f in ca.check_incomplete_conditions([policy("no apps", apps=())])] == ["no apps"]


def test_device_compliance_flags_all_apps_policies_without_it():
    assert [f["policy"] for f in ca.check_device_compliance([policy("mfa only")])] == ["mfa only"]
    assert ca.check_device_compliance([policy(controls=("mfa", "compliantDevice"))]) == []


def test_user_exclusions_use_names_when_known_and_ids_otherwise():
    findings = ca.check_user_exclusions(
        [policy("P", exclude_users=("u-1", "u-2", "GuestsOrExternalUsers"))], {"u-1": "breakglass@example.com"}
    )
    assert findings[0]["detail"].startswith("Excludes: breakglass@example.com, u-2.")


def test_policies_with_null_sections_do_not_crash():
    sparse = [{"displayName": "sparse", "state": "enabled", "conditions": None, "grantControls": None, "sessionControls": None}]
    assert isinstance(ca.evaluate(sparse), list)


def test_command_succeeds_on_a_tenant_that_passes_checks(run_json):
    """Regression: a passing check used to crash the whole command."""
    results = run_json(["evaluate-conditional-access-policies"], FakeGraph({POLICIES: WELL_CONFIGURED}))
    assert all(f["severity"] == "INFO" for f in results)


def test_command_resolves_excluded_users_one_by_one(run_json):
    graph = FakeGraph(
        {
            POLICIES: [policy("P", exclude_users=("u-1", "u-gone"))],
            "v1.0/users/u-1": {"id": "u-1", "userPrincipalName": "breakglass@example.com"},
            "v1.0/users/u-gone": GraphError("gone", status=404),
        }
    )
    results = run_json(["evaluate-conditional-access-policies"], graph)
    detail = next(f["detail"] for f in results if f["check"] == "Per-User Exclusions Present")
    assert "breakglass@example.com, u-gone" in detail
    assert not any(path == "v1.0/users" for path, _ in graph.calls)


def test_command_skips_user_lookups_below_info(run_json):
    graph = FakeGraph({POLICIES: [policy("P", exclude_users=("u-1",))]})
    run_json(["evaluate-conditional-access-policies", "--threshold", "HIGH"], graph)
    assert [path for path, _ in graph.calls] == [POLICIES]


def test_an_invalid_threshold_is_rejected(run):
    code, out, err = run(["evaluate-conditional-access-policies", "--threshold", "critical"], FakeGraph({POLICIES: []}))
    assert code == 2
    assert out == ""
