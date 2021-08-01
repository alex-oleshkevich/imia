import abc
import enum
import typing as t

from kupala.types import ASGIApp
from kupala.requests import Request


class AuthenticationError(Exception):
    """Base class for all authentication related errors."""


class NotAuthenticatedError(AuthenticationError):
    """Raised when the user is not authenticated while service the request."""


class ImpersonationNotAllowedError(AuthenticationError):
    """Raised when the user is not allowed to perform impersonation."""


class InactiveUserError(AuthenticationError):
    """Raised when the user account is inactive."""


class LoginState(enum.Enum):
    ANONYMOUS = "ANONYMOUS"
    IMPERSONATOR = "IMPERSONATOR"
    REMEMBERED = "REMEMBERED"
    FULLY_AUTHENTICATED = "FULLY_AUTHENTICATED"


class UserLike(t.Protocol):
    def get_identifier(self) -> t.Any:
        ...

    def get_scopes(self) -> list[str]:
        ...


class UserToken:
    __slots__ = ["_user", "_scopes", "_state", "_original_user"]

    def __init__(
        self,
        user: UserLike,
        scopes: list[str],
        state: LoginState,
        original_user: UserLike = None,
    ) -> None:
        self._user = user
        self._scopes = scopes or []
        self._state = state
        self._original_user = original_user

    @property
    def is_authenticated(self) -> bool:
        return self.state in [LoginState.REMEMBERED, LoginState.FRESH]

    @property
    def is_anonymous(self) -> bool:
        return not self.is_authenticated

    @property
    def is_impersonator(self) -> bool:
        return self.state == LoginState.IMPERSONATOR

    @property
    def scopes(self) -> list[str]:
        return self._scopes

    @property
    def user(self) -> UserLike:
        return self._user

    @property
    def state(self) -> LoginState:
        return self._state

    @property
    def original_user(self) -> UserLike:
        return self._original_user


class UserProvider(abc.ABC):
    """User provides perform user look ups over data storages.
    These classes are consumed by Authenticator instances
    and are not designed to be a part of login or logout process."""

    async def find_by_identifier(self, identifier: object) -> t.Optional[UserLike]:
        """Look up a user by ID."""
        raise NotImplementedError()

    async def find_by_identity(self, identity: object) -> t.Optional[UserLike]:
        """Look up a user by it's identity. Where identity may be an email address, or username."""
        raise NotImplementedError()

    async def find_by_token(self, token: str) -> t.Optional[UserLike]:
        """Look up a user using API token."""
        raise NotImplementedError()


class InMemoryProvider(UserProvider):
    """A user provides that uses a predefined map of users."""

    def __init__(self, user_map: dict[str, UserLike]) -> None:
        self.user_map = user_map

    async def find_by_identifier(self, identifier: object) -> t.Optional[UserLike]:
        return self.user_map.get(identifier)

    async def find_by_identity(self, identity: object) -> t.Optional[UserLike]:
        return self.user_map.get(identity)

    async def find_by_token(self, token: str) -> t.Optional[UserLike]:
        return self.user_map.get(token)


class Authenticator(abc.ABC):
    """Authenticators load user using request data.
    For example, an authenticate may use session to get user's ID
    and load user instance from a user provider.
    Another example can be when you load a user by API token read from headers.

    Authenticators are part of AuthenticationMiddleware.
    """

    async def authenticate(self, request: Request) -> t.Optional[UserToken]:
        raise NotImplementedError()


class BasicAuthenticator(Authenticator):
    """Basic authenticator supports WWW-Basic authentication type."""

    def __init__(self, users: UserProvider) -> None:
        self.users = users


class SessionAuthenticator(Authenticator):
    """Session authenticator will use session to get an ID of a user."""

    def __init__(self, users: UserProvider) -> None:
        self.users = users


class TokenAuthenticator(Authenticator):
    """Token authenticator reads Authorization header
    to obtain an API token and load a user using it."""

    token_type: str = None

    def __init__(self, users: UserProvider, token_type: str) -> None:
        self.users = users
        self.token_type = token_type or self.token_type


class BearerAuthenticator(Authenticator):
    """Bearer authenticator is a subtype of TokenAuthenticator designed for Bearer token types."""

    token_type = "Bearer"

    def __init__(self, users: UserProvider) -> None:
        self.users = users


def impersonate(request: Request, user: UserLike) -> None:
    """Activate impersonation."""


def is_impersonator(request: Request) -> bool:
    """Test if the impersonation is active."""


def exit_impersonation(request: Request) -> None:
    """Exit the impersonation session (restores to an original user)."""


def get_original_user(request: Request) -> None:
    """Get the original user when the impersonation is active."""


class ImpersonationMiddleware:
    """A middleware used to temporary impersonate another user."""

    def __init__(
        self,
        app: ASGIApp,
        user_provider: UserProvider,
        query_param: str = "_impersonate",
        exit_query_param: str = "__exit__",
        header_name: str = "x-switch-user",
    ) -> None:
        pass


class AuthenticationMiddleware:
    """Authenticator middleware will load a user from the request using authenticators.
    If the user can be found Request.auth property will become available.
    """

    def __init__(
        self,
        app: ASGIApp,
        authenticators: list[Authenticator],
        on_failure: str = "raise",
        redirect_to: str = "/",
        exclude: list[str] = None,
    ) -> None:
        pass


class LoginManager:
    """Use this class to handle login and logout forms."""

    def authenticate(self, request: Request) -> t.Optional[UserToken]:
        pass

    def login(
        self, request: Request, identity: str, credential: str
    ) -> t.Optional[UserToken]:
        """
        find user in the db
        check password
        write id to session
        regenerate csrf token
        check session key and regen session if token is used (see django.contrib.auth.login)
        """

    def set_user(self, request: Request, user: UserLike) -> None:
        pass

    def logout(self, request: Request) -> None:
        pass


async def login(request: Request, identity: str, credential: str) -> UserToken:
    return LoginManager().login(request, identity, credential)


async def logout(request: Request):
    return LoginManager().logout(request)
