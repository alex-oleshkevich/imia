from __future__ import annotations

import abc
import base64
import re
import typing as t
from starlette.requests import HTTPConnection
from starlette.responses import RedirectResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from .exceptions import AuthenticationError
from .login import get_session_auth_id
from .protocols import PasswordVerifier, UserLike
from .user_providers import UserProvider
from .user_token import AnonymousUser, LoginState, UserToken


class WWWAuthenticationRequiredError(Exception):
    pass


class BaseAuthenticator(abc.ABC):  # pragma: no cover
    """
    Authenticators load user using request data. For example, an authenticate
    may use session to get user's ID and load user instance from a user
    provider. Another example can be when you load a user by API token read from
    headers.

    Authenticators are part of AuthenticationMiddleware.
    """

    async def authenticate(self, connection: HTTPConnection) -> t.Optional[UserLike]:
        raise NotImplementedError()

    def get_auth_header(self) -> t.Optional[str]:
        return None


class HTTPBasicAuthenticator(BaseAuthenticator):
    """Basic authenticator supports WWW-Basic authentication type."""

    def __init__(
        self,
        user_provider: UserProvider,
        password_verifier: PasswordVerifier,
        realm: str = 'Protected access',
    ) -> None:
        self.user_provider = user_provider
        self.password_verifier = password_verifier
        self.realm = realm

    async def authenticate(self, connection: HTTPConnection) -> t.Optional[UserLike]:
        header = connection.headers.get('authorization')
        if not header or not header.lower().startswith('basic'):
            raise WWWAuthenticationRequiredError()

        try:
            username, password = base64.b64decode(header[6:]).decode().split(':')
            if password == '':
                raise ValueError('Empty password.')
        except ValueError:
            return None

        user = await self.user_provider.find_by_username(username)
        if not user:
            return None

        if self.password_verifier.verify(password, user.get_hashed_password()):
            return user

        return None

    def get_auth_header(self) -> t.Optional[str]:
        return 'Basic realm="%s"' % self.realm


class SessionAuthenticator(BaseAuthenticator):
    """Session authenticator will use session to get an ID of a user."""

    def __init__(self, user_provider: UserProvider) -> None:
        self.user_provider = user_provider

    async def authenticate(self, connection: HTTPConnection) -> t.Optional[UserLike]:
        user_id = get_session_auth_id(connection)
        if user_id is None:
            return None

        return await self.user_provider.find_by_id(user_id)


class TokenAuthenticator(BaseAuthenticator):
    """Token authenticator reads Authorization header to obtain an API token and
    load a user using it."""

    def __init__(self, user_provider: UserProvider, token_name: str) -> None:
        self.user_provider = user_provider
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
            if token_name.lower() != self.token_name.lower():
                return None
            return await self.user_provider.find_by_token(token_value)


class BearerAuthenticator(TokenAuthenticator):
    """Bearer authenticator is a subtype of TokenAuthenticator designed for
    Bearer token types."""

    def __init__(self, user_provider: UserProvider) -> None:
        super().__init__(user_provider, 'Bearer')


class APIKeyAuthenticator(BaseAuthenticator):
    """
    API key is a simple way to use token authentication.

    The basic principle is to read token from query params, and fallback to
    headers if none found.
    """

    def __init__(self, user_provider: UserProvider, query_param: str = 'apikey', header_name: str = 'X-Api-Key'):
        self.user_provider = user_provider
        self.query_param = query_param
        self.header_name = header_name

    async def authenticate(self, connection: HTTPConnection) -> t.Optional[UserLike]:
        token = self._get_token_from_query_params(connection)
        token = token or self._get_token_from_header(connection)
        if token:
            return await self.user_provider.find_by_token(token)
        return None

    def _get_token_from_query_params(self, connection: HTTPConnection) -> t.Optional[str]:
        return connection.query_params.get(self.query_param)

    def _get_token_from_header(self, connection: HTTPConnection) -> t.Optional[str]:
        return connection.headers.get(self.header_name)


class AuthenticationMiddleware:
    """
    Authenticator middleware will load a user from the request using
    authenticators.

    If the user can be found Request.auth property will become available.
    """

    def __init__(
        self,
        app: ASGIApp,
        authenticators: t.List[BaseAuthenticator],
        on_failure: str = "do_nothing",  # one of: raise, redirect, do_nothing
        redirect_to: str = "/",
        exclude_patterns: t.List[t.Union[str, t.Pattern]] = None,
        include_patterns: t.List[t.Union[str, t.Pattern]] = None,
    ) -> None:
        if on_failure == 'redirect' and redirect_to is None:
            raise ValueError(
                'redirect_to attribute of AuthenticationMiddleware cannot be None '
                'if on_failure is set to "redirect".'
            )

        if exclude_patterns is not None and include_patterns is not None:
            raise ValueError('"exclude_patterns" and "include_patterns" are mutially exclusive.')

        self._app = app
        self._authenticators = authenticators
        self._on_failure = on_failure
        self._redirect_to = redirect_to
        self._exclude_patterns = exclude_patterns or []
        self._include_patterns = include_patterns

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ["http", "websocket"]:  # pragma: no cover
            await self._app(scope, receive, send)
            return

        # always populate scope['auth']
        scope['auth'] = UserToken(AnonymousUser(), LoginState.ANONYMOUS)

        request = HTTPConnection(scope)
        if self._should_interrupt(request):
            return await self._app(scope, receive, send)

        user: t.Optional[UserLike] = None
        for authenticator in self._authenticators:
            try:
                user = await authenticator.authenticate(request)
                if user:
                    break
            except WWWAuthenticationRequiredError:
                auth_header = authenticator.get_auth_header()
                if auth_header:
                    response = Response(None, headers={'WWW-Authenticate': auth_header}, status_code=401)
                    return await response(scope, receive, send)

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

    def _should_interrupt(self, request: HTTPConnection) -> bool:
        for pattern in self._exclude_patterns:
            if re.search(pattern, str(request.url)):
                return True

        return bool(
            self._include_patterns
            and not any(re.search(pattern, str(request.url)) for pattern in self._include_patterns)
        )
