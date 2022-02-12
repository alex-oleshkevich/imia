import typing as t
from starlette.requests import HTTPConnection
from starlette.types import ASGIApp, Receive, Scope, Send

from .exceptions import AuthenticationError
from .protocols import UserLike
from .user_providers import UserProvider
from .user_token import LoginState, UserToken

IMPERSONATION_SESSION_KEY = '_impersonated_user_id'


class ImpersonationNotAllowedError(AuthenticationError):
    """Raised when the user is not allowed to perform impersonation."""


class ImpersonationNotActiveError(AuthenticationError):
    """Raised when you try to access impersonation related data but the
    impersonation is not active."""


def impersonate(request: HTTPConnection, user: UserLike) -> None:
    """Activate impersonation."""
    request.scope['auth'] = UserToken(user, state=LoginState.IMPERSONATOR, original_user_token=request.scope['auth'])
    if 'session' in request.scope:
        request.scope['session'][IMPERSONATION_SESSION_KEY] = user.get_id()


def exit_impersonation(request: HTTPConnection) -> None:
    """Exit the impersonation session (restores to an original user)."""
    if 'session' in request.scope:
        request.scope['session'].pop(IMPERSONATION_SESSION_KEY, None)


def impersonation_is_active(request: HTTPConnection) -> bool:
    return request.scope['auth'].original_user_id is not None


def get_original_user(request: HTTPConnection) -> UserLike:
    """Get the original user when the impersonation is active."""
    return (
        request.scope['auth'].original_user_token.user
        if request.scope['auth'].original_user_token
        else request.scope['auth'].user
    )


class ImpersonationMiddleware:
    """A middleware used to temporary impersonate another user."""

    def __init__(
        self,
        app: ASGIApp,
        user_provider: UserProvider,
        guard_fn: t.Callable[[UserToken, HTTPConnection], bool] = None,
        enter_query_param: str = "_impersonate",
        exit_user_name: str = "__exit__",
        scope: str = 'auth:impersonate_others',
    ) -> None:
        self._app = app
        self._user_provider = user_provider
        self._guard_fn = guard_fn
        self._enter_query_param = enter_query_param
        self._exit_user_name = exit_user_name
        self._scope = scope

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ["http", "websocket"]:  # pragma: no cover
            await self._app(scope, receive, send)
            return

        request = HTTPConnection(scope)
        action, impersonation_target = self._detect_action(request)
        if action == 'ignore':
            # user haven't asked anything we can offer
            return await self._app(scope, receive, send)

        if 'auth' not in request.scope:
            raise ValueError('ImpersonationMiddleware needs AuthenticationMiddleware to be installed.')

        if not self._can_enter_impersonation(request):
            return await self._app(scope, receive, send)

        if action == 'enter':
            user_id = request.query_params[self._enter_query_param]
            await self._enter_impersonation(request, user_id)

        if action == 'exit':
            await self._exit_impersonation(request)

        if action == 'activate':
            await self._enter_impersonation(request, impersonation_target)

        await self._app(scope, receive, send)

    async def _enter_impersonation(self, request: HTTPConnection, user_id: str) -> None:
        user = await self._user_provider.find_by_id(user_id)
        if user:
            impersonate(request, user)

    async def _exit_impersonation(self, request: HTTPConnection) -> None:
        exit_impersonation(request)

    def _can_enter_impersonation(self, request: HTTPConnection) -> bool:
        """
        Test if current user can impersonate other.

        Here are two checks. The first one to lookup a presence of self._scope
        in token scopes. The other one is to provide guard functions that must
        return boolean value. The guard function take the precedence when
        available.
        """
        if self._guard_fn:
            # forbid impersonation if guard function returns False
            return self._guard_fn(request.auth, request)

        # user must have "can_impersonate" scope
        return self._scope in request.auth

    def _detect_action(self, request: HTTPConnection) -> t.Tuple[str, str]:
        username = request.query_params.get(self._enter_query_param)
        if username is None:
            impersonation_target = request.scope.get('session', {}).get(IMPERSONATION_SESSION_KEY)
            if impersonation_target is not None:
                return 'activate', impersonation_target
            return 'ignore', ''

        if username == self._exit_user_name:
            return 'exit', ''

        return 'enter', username
