class AuthenticationError(Exception):
    """Base class for all authentication related errors."""


class NotAuthenticatedError(AuthenticationError):
    """Raised when the user is not authenticated while service the request."""


class InactiveUserError(AuthenticationError):
    """Raised when the user account is inactive."""


class SessionReusageError(AuthenticationError):
    """Raise when another user tries to reuse other user session."""
