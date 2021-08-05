class AuthenticationError(Exception):
    """Base class for all authentication related errors."""


class SessionReusageError(AuthenticationError):
    """Raise when another user tries to reuse other user session."""
