import abc
import enum
import hashlib
import hmac
import secrets
import typing as t

from asgiref.typing import ASGIApplication as ASGIApp

SESSION_KEY = '_auth_user_id'
SESSION_HASH = '_auth_user_hash'
HASHING_ALGORITHM = 'sha1'


class _State(t.Protocol):
    def __getattr__(self, item: str) -> t.Any: ...

    def __setattr__(self, item: str, value: t.Any) -> t.Any: ...


class Request(t.Protocol):
    session: t.MutableMapping
    state: _State


class AuthenticationError(Exception):
    """Base class for all authentication related errors."""


class NotAuthenticatedError(AuthenticationError):
    """Raised when the user is not authenticated while service the request."""


class ImpersonationNotAllowedError(AuthenticationError):
    """Raised when the user is not allowed to perform impersonation."""


class InactiveUserError(AuthenticationError):
    """Raised when the user account is inactive."""


class SessionReusageError(AuthenticationError):
    """Raise when another user tries to reuse other user session."""


class PasswordVerifier(t.Protocol):
    def verify(self, plain: str, hashed: str) -> bool: ...


class LoginState(enum.Enum):
    ANONYMOUS = "ANONYMOUS"
    IMPERSONATOR = "IMPERSONATOR"
    REMEMBERED = "REMEMBERED"
    FRESH = "FRESH"


class UserLike(t.Protocol):
    def get_display_name(self) -> str: ...

    def get_identifier(self) -> t.Any: ...

    def get_raw_password(self) -> str: ...

    def get_scopes(self) -> list[str]: ...


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
    def display_name(self) -> str:
        return self.user.get_display_name()

    @property
    def state(self) -> LoginState:
        return self._state

    @property
    def original_user(self) -> UserLike:
        return self._original_user

    def __bool__(self) -> bool:
        return self.is_authenticated

    def __str__(self) -> str:
        return self.display_name

    def __contains__(self, item: str) -> bool:
        return item in self.scopes


class AnonymousUser:
    def get_display_name(self) -> str:
        return 'Anonymous'

    def get_identifier(self) -> t.Any:
        return None

    def get_raw_password(self) -> str:
        return ''

    def get_scopes(self) -> list[str]:
        return []


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

    async def find_by_identifier(self, identifier: str) -> t.Optional[UserLike]:
        return self.user_map.get(identifier)

    async def find_by_identity(self, identity: str) -> t.Optional[UserLike]:
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


def get_session_auth_id(requset: Request) -> t.Optional[str]:
    return requset.session.get(SESSION_KEY)


def get_session_auth_hash(request: Request) -> t.Optional[str]:
    return request.session.get(SESSION_HASH)


def update_session_auth_hash(request: Request, user: UserLike, secret_key: str) -> None:
    """Update current session's SESSION_HASH key.
    Call this function in your password reset form otherwise you will be logged out."""
    if hasattr(request.session, 'regenerate_id'):
        request.session.regenerate_id()
    request.session[SESSION_HASH] = _get_password_hmac_from_user(user, secret_key)


def _get_password_hmac_from_user(user: UserLike, secret: str) -> str:
    """Generate HMAC value for user's password."""
    key = "imia.session.hash" + secret
    key = hashlib.sha256(key.encode()).digest()
    return hmac.new(key, msg=user.get_raw_password().encode(), digestmod=hashlib.sha1).hexdigest()


def _check_for_other_user_session(request: Request, user: UserLike, user_password_hmac: str) -> None:
    """There is a chance that session may already contain data of another user.
    This may happen if you don't clear session property on logout, or SESSION_KEY is set from the outside.
    In this case we need to run several security checks to ensure that SESSION_KEY is valid.

    Our plan:
        * if SESSION_KEY and ID of current user is not the same -> risk of session re-usage
        * if session hash is not the same as hash for user's password then we clearly reusing other's session.
    """
    session_auth_hmac = get_session_auth_hash(request)
    if SESSION_KEY in request.session and any([
        # if we have other user id in the session
        request.session[SESSION_KEY] != str(user.get_identifier()),
        # and session has previously set hash, and hashes are not equal
        session_auth_hmac and not secrets.compare_digest(session_auth_hmac, user_password_hmac),
    ]):
        # probably this is the session of another user -> clear
        raise SessionReusageError()


async def login_user(request: Request, user: UserLike, secret_key: str) -> UserToken:
    """Login a user w/o password check."""
    user_password_hmac = _get_password_hmac_from_user(user, secret_key)
    try:
        _check_for_other_user_session(request, user, user_password_hmac)
    except SessionReusageError:
        request.session.clear()
    else:
        if hasattr(request.session, 'regenerate_id'):
            # if session implements `def regenerate_id(self) -> str` then call it
            await request.session.regenerate_id()

    user_token = UserToken(user=user, scopes=user.get_scopes(), state=LoginState.FRESH)
    request.session[SESSION_KEY] = str(user.get_identifier())
    request.session[SESSION_HASH] = user_password_hmac
    request.state.user_token = user_token
    return user_token


class LoginManager:
    """Use this class to handle login and logout forms."""

    def __init__(self, user_provider: UserProvider, password_verifier: PasswordVerifier, secret_key: str = '') -> None:
        self._user_provider = user_provider
        self._password_verifier = password_verifier
        self._secret_key = secret_key

    async def login(self, request: Request, username: str, password: str) -> UserToken:
        user = await self._user_provider.find_by_identity(username)
        if user is not None and self._password_verifier.verify(password, user.get_raw_password()):
            return await login_user(request, user, self._secret_key)
        return UserToken(user=AnonymousUser(), scopes=[], state=LoginState.ANONYMOUS)

    def logout(self, request: Request) -> None:
        request.session.pop(SESSION_KEY, None)
        request.session.pop(SESSION_HASH, None)
        request.state.user_token = UserToken(user=AnonymousUser(), scopes=[], state=LoginState.ANONYMOUS)
