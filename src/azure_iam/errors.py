class AzureIamError(Exception):
    """Base class for errors that should end the command with a message."""


class AuthError(AzureIamError):
    """Could not obtain a Microsoft Graph token."""


class NotFoundError(AzureIamError):
    """A role, permission or other named object does not exist."""


class GraphError(AzureIamError):
    """Microsoft Graph returned an error or an unusable response."""

    def __init__(self, message, status=None, code=None):
        super().__init__(message)
        self.status = status
        self.code = code
