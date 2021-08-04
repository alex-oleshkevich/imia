import abc
import base64
import enum
import hashlib
import hmac
import re
import secrets
import typing as t
from starlette.requests import HTTPConnection
from starlette.responses import RedirectResponse
from starlette.types import ASGIApp, Receive, Scope, Send

SESSION_KEY = '_auth_user_id'
SESSION_HASH = '_auth_user_hash'
HASHING_ALGORITHM = 'sha1'


class Request(t.Protocol):
    session: t.MutableMapping
    scope: t.MutableMapping


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


class PasswordVerifier(t.Protocol):  # pragma: no cover
    def verify(self, plain: str, hashed: str) -> bool:
        ...


class LoginState(enum.Enum):
    ANONYMOUS = "ANONYMOUS"
    IMPERSONATOR = "IMPERSONATOR"
    REMEMBERED = "REMEMBERED"
    FRESH = "FRESH"


class UserLike(t.Protocol):  # pragma: no cover
    def get_display_name(self) -> str:
        ...

    def get_identifier(self) -> t.Any:
        ...

    def get_hashed_password(self) -> str:
        ...

    def get_scopes(self) -> t.List[str]:
        ...


class UserToken:
    __slots__ = ["_user", "_scopes", "_state"]

    def __init__(
        self,
        user: UserLike,
        state: LoginState,
        original_user_id: t.Any = None,
    ) -> None:
        self._user = user
        self._state = state

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
    def scopes(self) -> t.List[str]:
        return self.user.get_scopes()

    @property
    def identity(self) -> t.Any:
        return self.user.get_identifier()

    @property
    def user(self) -> UserLike:
        return self._user

    @property
    def display_name(self) -> str:
        return self.user.get_display_name()

    @property
    def state(self) -> LoginState:
        return self._state

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

    def get_hashed_password(self) -> str:
        return ''

    def get_scopes(self) -> t.List[str]:
        return []


class UserProvider(abc.ABC):  # pragma: no cover
    """User provides perform user look ups over data storages.
    These classes are consumed by Authenticator instances
    and are not designed to be a part of login or logout process."""

    async def find_by_id(self, identifier: t.Any) -> t.Optional[UserLike]:
        """Look up a user by ID."""
        raise NotImplementedError()

    async def find_by_username(self, username_or_email: str) -> t.Optional[UserLike]:
        """Look up a user by it's identity. Where identity may be an email address, or username."""
        raise NotImplementedError()

    async def find_by_token(self, token: str) -> t.Optional[UserLike]:
        """Look up a user using API token."""
        raise NotImplementedError()


class InMemoryProvider(UserProvider):
    """A user provides that uses a predefined map of users."""

    def __init__(self, user_map: t.Mapping[str, UserLike]) -> None:
        self.user_map = user_map

    async def find_by_id(self, identifier: str) -> t.Optional[UserLike]:
        return self.user_map.get(identifier)

    async def find_by_username(self, username_or_email: str) -> t.Optional[UserLike]:
        return self.user_map.get(username_or_email)

    async def find_by_token(self, token: str) -> t.Optional[UserLike]:
        return self.user_map.get(token)


class Authenticator(abc.ABC):  # pragma: no cover
    """Authenticators load user using request data.
    For example, an authenticate may use session to get user's ID
    and load user instance from a user provider.
    Another example can be when you load a user by API token read from headers.

    Authenticators are part of AuthenticationMiddleware.
    """

    async def authenticate(self, connection: HTTPConnection) -> t.Optional[UserLike]:
        raise NotImplementedError()


class BasicAuthenticator(Authenticator):
    """Basic authenticator supports WWW-Basic authentication type."""

    def __init__(self, users: UserProvider, password_verifier: PasswordVerifier) -> None:
        self.users = users
        self.password_verifier = password_verifier

    async def authenticate(self, connection: HTTPConnection) -> t.Optional[UserLike]:
        header = connection.headers.get('authorization')
        if not header or not header.lower().startswith('basic'):
            return None

        try:
            username, password = base64.b64decode(header[6:]).decode().split(':')
            if password == '':
                raise ValueError('Empty password.')
        except ValueError:
            return None

        user = await self.users.find_by_username(username)
        if not user:
            return None

        if self.password_verifier.verify(password, user.get_hashed_password()):
            return user

        return None


class SessionAuthenticator(Authenticator):
    """Session authenticator will use session to get an ID of a user."""

    def __init__(self, users: UserProvider) -> None:
        self.users = users

    async def authenticate(self, connection: HTTPConnection) -> t.Optional[UserLike]:
        user_id = get_session_auth_id(connection)
        if user_id is None:
            return None

        return await self.users.find_by_id(user_id)


class TokenAuthenticator(Authenticator):
    """Token authenticator reads Authorization header
    to obtain an API token and load a user using it."""

    def __init__(self, users: UserProvider, token_name: str) -> None:
        self.users = users
        self.token_name = token_name

    async def authenticate(self, connection: HTTPConnection) -> t.Optional[UserLike]:
        header = connection.headers.get('authorization')
        if not header:
            return None
        try:
            token_name, token_value = header.split(' ')
        except ValueError:
            return None
        else:
            if token_name != self.token_name:
                return None
            return await self.users.find_by_token(token_value)


class BearerAuthenticator(TokenAuthenticator):
    """Bearer authenticator is a subtype of TokenAuthenticator designed for Bearer token types."""

    def __init__(self, users: UserProvider) -> None:
        super().__init__(users, 'Bearer')


class APIKeyAuthenticator(Authenticator):
    """API key is a simple way to use token authentication.
    The basic principle is to read token from query params, and fallback to headers if none found."""

    def __init__(self, users: UserProvider, query_param: str = 'apikey', header_name: str = 'X-Api-Key'):
        self.users = users
        self.query_param = query_param
        self.header_name = header_name

    async def authenticate(self, connection: HTTPConnection) -> t.Optional[UserLike]:
        token = self._get_token_from_query_params(connection)
        token = token or self._get_token_from_header(connection)
        if token:
            return await self.users.find_by_token(token)
        return None

    def _get_token_from_query_params(self, connection: HTTPConnection) -> t.Optional[str]:
        return connection.query_params.get(self.query_param)

    def _get_token_from_header(self, connection: HTTPConnection) -> t.Optional[str]:
        return connection.headers.get(self.header_name)


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
        authenticators: t.List[Authenticator],
        on_failure: str = "do_nothing",  # one of: raise, redirect, do_nothing
        redirect_to: str = "/",
        exclude: t.List[t.Union[str, t.Pattern]] = None,
    ) -> None:
        self._app = app
        self._authenticators = authenticators
        self._on_failure = on_failure
        self._redirect_to = redirect_to
        self._exclude = exclude or []

        if on_failure == 'redirect' and redirect_to is None:
            raise ValueError(
                'redirect_to attribute of AuthenticationMiddleware cannot be None '
                'if on_failure is set to "redirect".'
            )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ["http", "websocket"]:  # pragma: no cover
            await self._app(scope, receive, send)
            return

        # always populate scope['auth']
        scope['auth'] = UserToken(AnonymousUser(), LoginState.ANONYMOUS)

        request = HTTPConnection(scope)
        for pattern in self._exclude:
            if re.search(pattern, str(request.url)):
                return await self._app(scope, receive, send)

        user: t.Optional[UserLike] = None
        for authenticator in self._authenticators:
            user = await authenticator.authenticate(request)
            if user:
                break

        if user:
            scope['auth'] = UserToken(user=user, state=LoginState.FRESH)
        elif self._on_failure == 'raise':
            raise AuthenticationError('Could not authenticate request.')
        elif self._on_failure == 'redirect':
            response = RedirectResponse(self._redirect_to)
            return await response(scope, receive, send)
        elif self._on_failure != 'do_nothing':
            raise ValueError(
                'Unsupported action passed to AuthenticationMiddleware via on_failure argument: '
                '%s.' % self._on_failure
            )
        await self._app(scope, receive, send)


def get_session_auth_id(connection: HTTPConnection) -> t.Optional[str]:
    return connection.session.get(SESSION_KEY)


def get_session_auth_hash(connection: HTTPConnection) -> t.Optional[str]:
    return connection.session.get(SESSION_HASH)


async def update_session_auth_hash(request: Request, user: UserLike, secret_key: str) -> None:
    """Update current session's SESSION_HASH key.
    Call this function in your password reset form otherwise you will be logged out."""
    if hasattr(request.session, 'regenerate_id'):
        await request.session.regenerate_id()  # type: ignore
    request.session[SESSION_HASH] = _get_password_hmac_from_user(user, secret_key)


def _get_password_hmac_from_user(user: UserLike, secret: str) -> str:
    """Generate HMAC value for user's password."""
    key = hashlib.sha256(("imia.session.hash" + secret).encode()).digest()
    return hmac.new(key, msg=user.get_hashed_password().encode(), digestmod=hashlib.sha1).hexdigest()


def _check_for_other_user_session(connection: HTTPConnection, user: UserLike, user_password_hmac: str) -> None:
    """There is a chance that session may already contain data of another user.
    This may happen if you don't clear session property on logout, or SESSION_KEY is set from the outside.
    In this case we need to run several security checks to ensure that SESSION_KEY is valid.

    Our plan:
        * if SESSION_KEY and ID of current user is not the same -> risk of session re-usage
        * if session hash is not the same as hash for user's password then we clearly reusing other's session.
    """
    session_auth_hmac = get_session_auth_hash(connection)
    if SESSION_KEY in connection.session and any(
        [
            # if we have other user id in the session
            connection.session[SESSION_KEY] != str(user.get_identifier()),
            # and session has previously set hash, and hashes are not equal
            session_auth_hmac and not secrets.compare_digest(session_auth_hmac, user_password_hmac),
        ]
    ):
        # probably this is the session of another user -> clear
        raise SessionReusageError()


async def login_user(request: HTTPConnection, user: UserLike, secret_key: str) -> UserToken:
    """Login a user w/o password check."""
    user_password_hmac = _get_password_hmac_from_user(user, secret_key)
    try:
        _check_for_other_user_session(request, user, user_password_hmac)
    except SessionReusageError:
        request.session.clear()
    else:
        if hasattr(request.session, 'regenerate_id'):
            # if session implements `def regenerate_id(self) -> str` then call it
            await request.session.regenerate_id()  # type: ignore

    user_token = UserToken(user=user, state=LoginState.FRESH)
    request.session[SESSION_KEY] = str(user.get_identifier())
    request.session[SESSION_HASH] = user_password_hmac
    request.scope['auth'] = user_token
    return user_token


class LoginManager:
    """Use this class to handle login and logout forms."""

    def __init__(self, user_provider: UserProvider, password_verifier: PasswordVerifier, secret_key: str = '') -> None:
        self._user_provider = user_provider
        self._password_verifier = password_verifier
        self._secret_key = secret_key

    async def login(self, request: HTTPConnection, username: str, password: str) -> UserToken:
        user = await self._user_provider.find_by_username(username)
        if user is not None and self._password_verifier.verify(password, user.get_hashed_password()):
            return await login_user(request, user, self._secret_key)
        return UserToken(user=AnonymousUser(), state=LoginState.ANONYMOUS)

    async def logout(self, request: HTTPConnection) -> None:
        request.session.clear()
        if hasattr(request.session, 'regenerate_id'):
            await request.session.regenerate_id()  # type: ignore

        request.scope['auth'] = UserToken(user=AnonymousUser(), state=LoginState.ANONYMOUS)
