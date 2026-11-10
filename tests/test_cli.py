import json

import pytest
from click.testing import CliRunner

from azure_iam.cli import main
from azure_iam.errors import AuthError, GraphError
from conftest import FakeGraph

POLICIES = "v1.0/identity/conditionalAccess/policies"

COMMANDS = [
    "find-risky-service-principals",
    "find-service-principals-with-permission",
    "find-role-members",
    "find-entra-roles-with-action",
    "find-privileged-users",
    "evaluate-conditional-access-policies",
]


def test_all_six_commands_are_registered():
    assert sorted(main.commands) == sorted(COMMANDS)


@pytest.mark.parametrize("command", COMMANDS)
def test_help_works_without_signing_in(run, command):
    code, out, _ = run([command, "--help"])
    assert code == 0
    assert "--credential-file" in out


def capture_settings(monkeypatch):
    seen = {}

    def fake_build(settings):
        seen.update(settings)
        return FakeGraph({POLICIES: []})

    monkeypatch.setattr("azure_iam.commands.common.build_client", fake_build)
    return seen


def test_sign_in_options_are_accepted_after_the_command(monkeypatch):
    seen = capture_settings(monkeypatch)
    result = CliRunner().invoke(
        main,
        ["evaluate-conditional-access-policies", "--azure-tenant-id", "t", "--credential-file", "x.env", "--auth", "app"],
    )
    assert result.exit_code == 0
    assert seen == {"azure_tenant_id": "t", "credential_file": "x.env", "auth": "app"}


def test_sign_in_options_are_accepted_before_the_command(monkeypatch):
    seen = capture_settings(monkeypatch)
    result = CliRunner().invoke(main, ["--credential-file", "x.env", "evaluate-conditional-access-policies"])
    assert result.exit_code == 0
    assert seen == {"credential_file": "x.env"}


def test_underscore_spellings_from_earlier_versions_still_work(monkeypatch):
    seen = capture_settings(monkeypatch)
    result = CliRunner().invoke(
        main,
        [
            "--credential_file", "group.env",
            "evaluate-conditional-access-policies",
            "--azure_tenant_id", "t", "--azure_client_id", "c", "--azure_client_secret", "s",
        ],
    )
    assert result.exit_code == 0
    assert seen == {
        "credential_file": "group.env",
        "azure_tenant_id": "t",
        "azure_client_id": "c",
        "azure_client_secret": "s",
    }


def test_an_option_after_the_command_overrides_one_before_it(monkeypatch):
    seen = capture_settings(monkeypatch)
    CliRunner().invoke(
        main, ["--azure-tenant-id", "first", "evaluate-conditional-access-policies", "--azure-tenant-id", "second"]
    )
    assert seen["azure_tenant_id"] == "second"


def test_stdout_is_always_json_on_success(run):
    code, out, err = run(["evaluate-conditional-access-policies"], FakeGraph({POLICIES: []}))
    assert code == 0
    assert isinstance(json.loads(out), list)
    assert err == ""


def test_graph_errors_go_to_stderr_with_exit_code_1(run):
    graph = FakeGraph({POLICIES: GraphError("Microsoft Graph request failed with HTTP 500", status=500)})
    code, out, err = run(["evaluate-conditional-access-policies"], graph)
    assert code == 1
    assert out == ""
    assert "HTTP 500" in err


def test_sign_in_errors_go_to_stderr_with_exit_code_1(monkeypatch):
    def fake_build(settings):
        raise AuthError("Run `az login` and try again.")

    monkeypatch.setattr("azure_iam.commands.common.build_client", fake_build)
    try:
        runner = CliRunner(mix_stderr=False)
    except TypeError:
        runner = CliRunner()
    result = runner.invoke(main, ["find-risky-service-principals"])
    assert result.exit_code == 1
    assert result.stdout == ""
    assert "az login" in result.stderr


def test_a_missing_required_option_is_a_usage_error(run):
    code, out, _ = run(["find-role-members"], FakeGraph())
    assert code == 2
    assert out == ""
