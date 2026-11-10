import base64
import json

import pytest
from click.testing import CliRunner

from azure_iam.cli import main
from azure_iam.errors import GraphError

HOME_TENANT = "11111111-1111-1111-1111-111111111111"
OTHER_TENANT = "99999999-9999-9999-9999-999999999999"


def make_token(**claims):
    """An unsigned token whose claims the tool can read for diagnostics."""
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"header.{payload}.signature"


class FakeAuth:
    name = "Azure CLI sign-in"

    def __init__(self, scopes="Directory.AccessAsUser.All", tenant=HOME_TENANT):
        self._scopes = scopes
        self._tenant = tenant
        self.refreshes = 0

    def get_token(self, force_refresh=False):
        if force_refresh:
            self.refreshes += 1
        return make_token(scp=self._scopes, tid=self._tenant)

    def granted_permissions(self):
        return sorted(self._scopes.split())

    def token_tenant_id(self):
        return self._tenant


class FakeGraph:
    """Stands in for GraphClient. Routes are matched by path prefix, longest first."""

    def __init__(self, routes=None, auth=None):
        self.routes = routes or {}
        self.auth = auth or FakeAuth()
        self.calls = []

    def _lookup(self, path, params):
        self.calls.append((path, params))
        for prefix in sorted(self.routes, key=len, reverse=True):
            if path.startswith(prefix):
                value = self.routes[prefix]
                if callable(value):
                    value = value(path, params)
                if isinstance(value, Exception):
                    raise value
                return value
        raise GraphError(f"no fake route for {path}", status=404)

    def get_all(self, path, params=None, headers=None):
        return self._lookup(path, params)

    def get_one(self, path, params=None, headers=None):
        return self._lookup(path, params)


@pytest.fixture
def run(monkeypatch):
    """Run the CLI against a FakeGraph. Returns (exit_code, stdout, stderr)."""

    def _run(args, graph=None, env=None):
        def fake_build(settings):
            if graph is None:
                raise AssertionError("this command should not have signed in")
            return graph

        monkeypatch.setattr("azure_iam.commands.common.build_client", fake_build)
        try:
            runner = CliRunner(mix_stderr=False)
        except TypeError:  # click >= 8.2 always keeps the streams apart
            runner = CliRunner()
        result = runner.invoke(main, args, env=env)
        return result.exit_code, result.stdout, result.stderr

    return _run


@pytest.fixture
def run_json(run):
    def _run_json(args, graph=None):
        code, out, err = run(args, graph)
        assert code == 0, f"exit {code}: {err}"
        return json.loads(out)

    return _run_json
