"""Checks for common gaps in conditional access policies.

Every check takes the tenant's policies and returns a list of findings, which
is empty when the check passes.
"""

import click

from azure_iam.commands.common import graph_command
from azure_iam.errors import GraphError

NEEDS = ("Policy.Read.All",)

ADMIN_ROLE_IDS = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "b0f54661-2d74-4c50-afa3-1ec803f12eba": "Billing Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "0526716b-113d-4c15-b2c8-68e3c22b9f80": "Authentication Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
}

# Values of includeUsers / excludeUsers that are not user object IDs.
USER_KEYWORDS = {"All", "None", "GuestsOrExternalUsers"}


def finding(severity, policy_name, check, detail):
    return {"severity": severity, "policy": policy_name, "check": check, "detail": detail}


def _enabled(policies):
    return [p for p in policies if p.get("state") == "enabled"]


def _controls(policy):
    return (policy.get("grantControls") or {}).get("builtInControls") or []


def _users(policy):
    return (policy.get("conditions") or {}).get("users") or {}


def _applications(policy):
    return (policy.get("conditions") or {}).get("applications") or {}


def _name(policy):
    return policy.get("displayName") or policy.get("id") or "unnamed policy"


def check_admin_mfa(policies):
    """MFA or block is enforced for every privileged role."""
    covered = set()
    for p in _enabled(policies):
        if "mfa" not in _controls(p) and "block" not in _controls(p):
            continue
        users = _users(p)
        if "All" in (users.get("includeUsers") or []):
            covered.update(ADMIN_ROLE_IDS)
        else:
            covered.update(users.get("includeRoles") or [])
    uncovered = [name for role_id, name in ADMIN_ROLE_IDS.items() if role_id not in covered]
    if uncovered:
        return [finding("HIGH", "N/A", "Admin MFA Coverage Gap", f"No MFA/block policy covers: {', '.join(uncovered)}")]
    return []


def check_legacy_auth(policies):
    """Legacy authentication is blocked. It bypasses MFA."""
    for p in _enabled(policies):
        client_apps = (p.get("conditions") or {}).get("clientAppTypes") or []
        if set(client_apps) >= {"exchangeActiveSync", "other"} and "block" in _controls(p):
            return []
    return [
        finding(
            "HIGH",
            "N/A",
            "Legacy Authentication Not Blocked",
            "No policy blocks legacy auth (Exchange ActiveSync + Other). "
            "Legacy auth bypasses MFA and is a frequent attack vector.",
        )
    ]


def check_no_grant_controls(policies):
    """Enabled policies that grant access with no controls at all."""
    return [
        finding(
            "HIGH",
            _name(p),
            "Unrestricted Access Grant",
            "Policy grants access with no controls (no MFA, no compliant device, no session policy).",
        )
        for p in _enabled(policies)
        if not p.get("grantControls") and not p.get("sessionControls")
    ]


def check_incomplete_conditions(policies):
    """Enabled policies with no application or user scope. They may never apply."""
    results = []
    for p in _enabled(policies):
        apps, users = _applications(p), _users(p)
        has_app = apps.get("includeApplications") or apps.get("includeUserActions")
        has_user = users.get("includeUsers") or users.get("includeRoles") or users.get("includeGroups")
        if not has_app or not has_user:
            results.append(
                finding(
                    "MEDIUM",
                    _name(p),
                    "Incomplete Policy Conditions",
                    "Policy is enabled but missing application or user scope. It may never trigger.",
                )
            )
    return results


def check_user_risk(policies):
    """High user risk triggers remediation. Requires Entra ID P2."""
    for p in _enabled(policies):
        risk = (p.get("conditions") or {}).get("userRiskLevels") or []
        if "high" in risk and any(c in _controls(p) for c in ("mfa", "block", "passwordChange")):
            return []
    return [
        finding(
            "MEDIUM",
            "N/A",
            "No High User Risk Policy",
            "No policy responds to HIGH user risk (compromised credentials). Requires Entra ID P2.",
        )
    ]


def check_all_user_mfa(policies):
    """Some policy enforces MFA for all users with no per-user exclusions."""
    for p in _enabled(policies):
        users = _users(p)
        if "All" in (users.get("includeUsers") or []) and not users.get("excludeUsers") and "mfa" in _controls(p):
            return []
    return [
        finding(
            "MEDIUM",
            "N/A",
            "No Universal MFA Policy",
            "No policy enforces MFA for ALL users with no exclusions. "
            "Consider an org-wide MFA baseline with deliberate exceptions.",
        )
    ]


def check_guest_mfa(policies):
    """MFA is enforced for guests and external users."""
    for p in _enabled(policies):
        included = _users(p).get("includeUsers") or []
        if ("GuestsOrExternalUsers" in included or "All" in included) and "mfa" in _controls(p):
            return []
    return [
        finding(
            "MEDIUM",
            "N/A",
            "Guest MFA Not Enforced",
            "No enabled policy enforces MFA for Guest or External users.",
        )
    ]


def check_sign_in_risk(policies):
    """High sign-in risk triggers MFA or block. Requires Entra ID P2."""
    for p in _enabled(policies):
        risk = (p.get("conditions") or {}).get("signInRiskLevels") or []
        if "high" in risk and ("mfa" in _controls(p) or "block" in _controls(p)):
            return []
    return [
        finding(
            "MEDIUM",
            "N/A",
            "No High Sign-In Risk Policy",
            "No policy responds to HIGH sign-in risk with MFA or block. Requires Entra ID P2.",
        )
    ]


def check_disabled_policies(policies):
    """Disabled policies provide no protection."""
    return [
        finding("INFO", _name(p), "Disabled Policy", "Policy is disabled and provides no protection.")
        for p in policies
        if p.get("state") == "disabled"
    ]


def check_report_only(policies):
    """Report-only policies that were never enforced."""
    return [
        finding(
            "INFO",
            _name(p),
            "Report-Only Mode",
            "Policy is in report-only mode. Verify this is intentional.",
        )
        for p in policies
        if p.get("state") == "enabledForReportingButNotEnforced"
    ]


def check_device_compliance(policies):
    """All-apps policies that do not require a compliant or hybrid-joined device."""
    results = []
    for p in _enabled(policies):
        if "All" not in (_applications(p).get("includeApplications") or []):
            continue
        if not any(c in _controls(p) for c in ("compliantDevice", "domainJoinedDevice")):
            results.append(
                finding(
                    "INFO",
                    _name(p),
                    "No Device Compliance Requirement",
                    "Policy targets ALL apps but doesn't require a compliant or hybrid-joined device.",
                )
            )
    return results


def check_persistent_browser(policies):
    """Some policy disables persistent browser sessions."""
    for p in _enabled(policies):
        persistent = (p.get("sessionControls") or {}).get("persistentBrowser") or {}
        if persistent.get("isEnabled") and persistent.get("mode") == "never":
            return []
    return [
        finding(
            "INFO",
            "N/A",
            "Persistent Browser Sessions Allowed",
            "No policy disables persistent browser sessions. "
            "Consider restricting for unmanaged/untrusted devices.",
        )
    ]


def excluded_user_ids(policies):
    ids = []
    for p in _enabled(policies):
        for user_id in _users(p).get("excludeUsers") or []:
            if user_id not in USER_KEYWORDS and user_id not in ids:
                ids.append(user_id)
    return ids


def check_user_exclusions(policies, user_names=None):
    """Per-user exclusions, listed so they can be confirmed as break-glass accounts."""
    user_names = user_names or {}
    results = []
    for p in _enabled(policies):
        excluded = [u for u in (_users(p).get("excludeUsers") or []) if u not in USER_KEYWORDS]
        if excluded:
            named = ", ".join(user_names.get(user_id, user_id) for user_id in excluded)
            results.append(
                finding(
                    "INFO",
                    _name(p),
                    "Per-User Exclusions Present",
                    f"Excludes: {named}. Confirm these are break-glass/emergency accounts only.",
                )
            )
    return results


HIGH_CHECKS = (check_admin_mfa, check_legacy_auth, check_no_grant_controls)
MEDIUM_CHECKS = (
    check_incomplete_conditions,
    check_user_risk,
    check_all_user_mfa,
    check_guest_mfa,
    check_sign_in_risk,
)
INFO_CHECKS = (check_disabled_policies, check_report_only, check_device_compliance, check_persistent_browser)


def evaluate(policies, threshold=None, user_names=None):
    """Run the checks at or above the threshold: high, medium, or info (everything)."""
    level = (threshold or "info").lower()
    checks = list(HIGH_CHECKS)
    if level in ("medium", "info"):
        checks += MEDIUM_CHECKS
    if level == "info":
        checks += INFO_CHECKS
    results = []
    for check in checks:
        results.extend(check(policies))
    if level == "info":
        results.extend(check_user_exclusions(policies, user_names))
    return results


def lookup_user_names(client, user_ids):
    """Best effort: an ID stays as it is if the user cannot be read."""
    names = {}
    for user_id in user_ids:
        try:
            user = client.get_one(f"v1.0/users/{user_id}", params={"$select": "id,userPrincipalName"})
        except GraphError as exc:
            if exc.status in (400, 403, 404):
                continue
            raise
        if user.get("userPrincipalName"):
            names[user_id] = user["userPrincipalName"]
    return names


@click.option(
    "--threshold",
    default=None,
    type=click.Choice(["high", "medium", "info"], case_sensitive=False),
    help="Lowest severity to report. high: high only. medium: high and medium. info (default): everything.",
)
@graph_command(
    "evaluate-conditional-access-policies",
    help="Find gaps and misconfigurations in conditional access policies.",
    needs=NEEDS,
)
def evaluate_conditional_access_policies(session, threshold):
    client = session.client
    policies = client.get_all("v1.0/identity/conditionalAccess/policies")
    user_names = {}
    if (threshold or "info").lower() == "info":
        user_names = lookup_user_names(client, excluded_user_ids(policies))
    return evaluate(policies, threshold, user_names)
