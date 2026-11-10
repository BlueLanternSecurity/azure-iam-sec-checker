"""A small read-only Microsoft Graph client."""

import time

import requests

from azure_iam.errors import GraphError

GRAPH_BASE = "https://graph.microsoft.com/"
RETRY_STATUSES = {429, 502, 503, 504}
MAX_RETRY_WAIT_SECONDS = 60


class GraphClient:
    def __init__(self, auth, session=None, max_retries=4, sleep=time.sleep, timeout=30):
        self.auth = auth
        self._session = session or requests.Session()
        self._max_retries = max_retries
        self._sleep = sleep
        self._timeout = timeout

    def get_all(self, path, params=None, headers=None):
        """Return every item of a collection, following all pages.

        Raises GraphError if any page fails, so a result is never partial.
        """
        items = []
        url, page_params = GRAPH_BASE + path, params
        while url:
            body = self._get(url, page_params, headers)
            if not isinstance(body.get("value"), list):
                raise GraphError(f"Microsoft Graph returned an unexpected response for {path}.")
            items.extend(body["value"])
            # The next link already carries the query; sending it again is an error.
            url, page_params = body.get("@odata.nextLink"), None
            if url and not url.startswith(GRAPH_BASE):
                raise GraphError("Microsoft Graph returned a next-page link to an unexpected host.")
        return items

    def get_one(self, path, params=None, headers=None):
        """Return a single object."""
        return self._get(GRAPH_BASE + path, params, headers)

    def _get(self, url, params, headers):
        refreshed = False
        attempt = 0
        while True:
            request_headers = dict(headers or {})
            request_headers["Authorization"] = f"Bearer {self.auth.get_token()}"
            try:
                response = self._session.get(
                    url, params=params, headers=request_headers, timeout=self._timeout
                )
            except requests.RequestException as exc:
                if attempt < self._max_retries:
                    self._sleep(2**attempt)
                    attempt += 1
                    continue
                raise GraphError(f"Could not reach Microsoft Graph: {exc}") from exc

            if response.status_code == 401 and not refreshed:
                self.auth.get_token(force_refresh=True)
                refreshed = True
                continue

            if response.status_code in RETRY_STATUSES and attempt < self._max_retries:
                self._sleep(self._retry_wait(response, attempt))
                attempt += 1
                continue

            if response.status_code >= 400:
                raise self._error(response)

            try:
                return response.json()
            except ValueError as exc:
                raise GraphError("Microsoft Graph returned a response that is not JSON.") from exc

    @staticmethod
    def _retry_wait(response, attempt):
        try:
            wait = float(response.headers.get("Retry-After", ""))
        except (TypeError, ValueError):
            wait = 2**attempt
        return max(0.0, min(wait, MAX_RETRY_WAIT_SECONDS))

    @staticmethod
    def _error(response):
        code, message = None, None
        try:
            error = response.json().get("error", {})
            if isinstance(error, dict):
                code, message = error.get("code"), error.get("message")
        except (ValueError, AttributeError):
            pass
        text = f"Microsoft Graph request failed with HTTP {response.status_code}"
        if code:
            text += f" ({code})"
        if message:
            text += f": {message}"
        return GraphError(text, status=response.status_code, code=code)
