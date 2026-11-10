import pytest
import requests

from azure_iam.errors import GraphError
from azure_iam.graph import GRAPH_BASE, GraphClient
from conftest import FakeAuth


class FakeResponse:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}

    def json(self):
        if self._body is None:
            raise ValueError("no body")
        return self._body


class FakeSession:
    def __init__(self, responses):
        self._responses = list(responses)
        self.requests = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.requests.append({"url": url, "params": params, "headers": headers})
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def make_client(responses, auth=None):
    waits = []
    session = FakeSession(responses)
    client = GraphClient(auth or FakeAuth(), session=session, sleep=waits.append)
    return client, session, waits


def test_follows_pages_without_resending_the_query():
    next_link = GRAPH_BASE + "v1.0/applications?$select=id&$skiptoken=abc"
    client, session, _ = make_client(
        [
            FakeResponse(body={"value": [{"id": "1"}], "@odata.nextLink": next_link}),
            FakeResponse(body={"value": [{"id": "2"}]}),
        ]
    )
    items = client.get_all("v1.0/applications", params={"$select": "id"})
    assert [i["id"] for i in items] == ["1", "2"]
    assert session.requests[0]["params"] == {"$select": "id"}
    assert session.requests[1]["url"] == next_link
    assert session.requests[1]["params"] is None


def test_a_failed_page_raises_instead_of_returning_partial_results():
    client, _, _ = make_client(
        [
            FakeResponse(body={"value": [{"id": "1"}], "@odata.nextLink": GRAPH_BASE + "v1.0/x?page=2"}),
            FakeResponse(status=400, body={"error": {"code": "BadRequest", "message": "nope"}}),
        ]
    )
    with pytest.raises(GraphError) as exc:
        client.get_all("v1.0/x")
    assert exc.value.status == 400
    assert "BadRequest" in str(exc.value) and "nope" in str(exc.value)


def test_refuses_a_next_link_to_another_host():
    client, session, _ = make_client(
        [FakeResponse(body={"value": [], "@odata.nextLink": "https://evil.example/v1.0/x"})]
    )
    with pytest.raises(GraphError):
        client.get_all("v1.0/x")
    assert len(session.requests) == 1


def test_refreshes_the_token_once_on_401():
    auth = FakeAuth()
    client, session, _ = make_client(
        [FakeResponse(status=401, body={"error": {"code": "InvalidAuthenticationToken"}}), FakeResponse(body={"value": []})],
        auth=auth,
    )
    assert client.get_all("v1.0/x") == []
    assert auth.refreshes == 1


def test_a_second_401_is_an_error():
    client, _, _ = make_client([FakeResponse(status=401, body={}), FakeResponse(status=401, body={})])
    with pytest.raises(GraphError) as exc:
        client.get_all("v1.0/x")
    assert exc.value.status == 401


def test_waits_as_told_when_throttled():
    client, _, waits = make_client(
        [FakeResponse(status=429, body={}, headers={"Retry-After": "7"}), FakeResponse(body={"value": [{"id": "1"}]})]
    )
    assert client.get_all("v1.0/x") == [{"id": "1"}]
    assert waits == [7.0]


def test_gives_up_after_repeated_throttling():
    client, _, waits = make_client([FakeResponse(status=429, body={})] * 5)
    with pytest.raises(GraphError) as exc:
        client.get_all("v1.0/x")
    assert exc.value.status == 429
    assert len(waits) == 4


def test_network_errors_are_retried_then_reported():
    client, _, _ = make_client([requests.ConnectionError("down")] * 5)
    with pytest.raises(GraphError, match="Could not reach Microsoft Graph"):
        client.get_all("v1.0/x")


def test_sends_the_bearer_token_and_does_not_mutate_caller_headers():
    headers = {"ConsistencyLevel": "eventual"}
    client, session, _ = make_client([FakeResponse(body={"value": []})])
    client.get_all("v1.0/x", headers=headers)
    assert headers == {"ConsistencyLevel": "eventual"}
    assert session.requests[0]["headers"]["Authorization"].startswith("Bearer ")


def test_a_response_without_a_value_list_is_an_error():
    client, _, _ = make_client([FakeResponse(body={"id": "single"})])
    with pytest.raises(GraphError):
        client.get_all("v1.0/x")
