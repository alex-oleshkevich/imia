import pytest
import typing as t
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from imia import (
    APIKeyAuthenticator,
    AuthenticationMiddleware,
    ImpersonationMiddleware,
    InMemoryProvider,
    SessionAuthenticator,
    get_original_user,
    impersonation_is_active,
    login_user,
)
from tests.conftest import User, inmemory_user_provider, user


async def login_view(request: Request) -> JSONResponse:
    await login_user(request, user, '')
    return JSONResponse({})


async def app_view(request: Request) -> JSONResponse:
    return JSONResponse(
        {
            'is_authenticated': request.auth.is_authenticated,
            'user_id': request.auth.user_id,
            'user_name': request.auth.display_name,
            'target_user': request.auth.original_user_id,
        }
    )


def test_stateless_impersonation() -> None:
    """Without session the _impersonate key must be always passed."""
    app = Starlette(
        debug=True,
        routes=[
            Route('/app', app_view),
        ],
        middleware=[
            Middleware(AuthenticationMiddleware, authenticators=[APIKeyAuthenticator(inmemory_user_provider)]),
            Middleware(ImpersonationMiddleware, user_provider=inmemory_user_provider, guard_fn=lambda c, u: True),
        ],
    )
    test_client = TestClient(app)
    response = test_client.get('/app?_impersonate=customer@localhost&apikey=root@localhost')
    assert response.json()['is_authenticated'] is True
    assert response.json()['user_id'] == 'customer@localhost'
    assert response.json()['target_user'] == 'root@localhost'

    # no _impersonate key -> no impersonation
    response = test_client.get('/app?apikey=root@localhost')
    assert response.json()['is_authenticated'] is True
    assert response.json()['user_id'] == 'root@localhost'
    assert response.json()['target_user'] is None


def test_stateful_impersonation() -> None:
    """With session the impersonation status must be kept between requests until
    deactivated."""
    app = Starlette(
        debug=True,
        routes=[
            Route('/login', login_view),
            Route('/app', app_view),
        ],
        middleware=[
            Middleware(SessionMiddleware, secret_key='key!'),
            Middleware(
                AuthenticationMiddleware,
                authenticators=[SessionAuthenticator(inmemory_user_provider)],
                include_patterns=['/app'],
            ),
            Middleware(ImpersonationMiddleware, user_provider=inmemory_user_provider, guard_fn=lambda c, u: True),
        ],
    )
    test_client = TestClient(app)

    # login first
    response = test_client.get('/login')
    assert response.status_code == 200

    # activate impersonation
    response = test_client.get('/app?_impersonate=customer@localhost')
    assert response.json()['is_authenticated'] is True
    assert response.json()['user_id'] == 'customer@localhost'
    assert response.json()['target_user'] == 'root@localhost'

    # now access same page another time -> impersonation must still be active
    response = test_client.get('/app')
    assert response.json()['is_authenticated'] is True
    assert response.json()['user_id'] == 'customer@localhost'
    assert response.json()['target_user'] == 'root@localhost'

    # now deactivate impersonation
    response = test_client.get('/app?_impersonate=__exit__')
    assert response.json()['is_authenticated'] is True
    assert response.json()['user_id'] == 'root@localhost'
    assert response.json()['target_user'] is None

    # # access one more time -> impersonation must be inactive
    response = test_client.get('/app')
    assert response.json()['is_authenticated'] is True
    assert response.json()['user_id'] == 'root@localhost'
    assert response.json()['target_user'] is None


def test_middleware_requires_auth_middleware() -> None:
    app = Starlette(
        debug=True,
        routes=[
            Route('/app', app_view),
        ],
        middleware=[
            Middleware(ImpersonationMiddleware, user_provider=inmemory_user_provider, guard_fn=lambda c, u: True),
        ],
    )
    test_client = TestClient(app)
    with pytest.raises(ValueError) as ex:
        test_client.get('/app?_impersonate=customer@localhost&apikey=root@localhost')
    assert str(ex.value) == 'ImpersonationMiddleware needs AuthenticationMiddleware to be installed.'


def test_guard_function_allows() -> None:
    app = Starlette(
        debug=True,
        routes=[
            Route('/app', app_view),
        ],
        middleware=[
            Middleware(AuthenticationMiddleware, authenticators=[APIKeyAuthenticator(inmemory_user_provider)]),
            Middleware(ImpersonationMiddleware, user_provider=inmemory_user_provider, guard_fn=lambda c, u: True),
        ],
    )
    test_client = TestClient(app)
    response = test_client.get('/app?_impersonate=customer@localhost&apikey=root@localhost')
    assert response.json()['user_id'] == 'customer@localhost'


def test_guard_function_denies() -> None:
    app = Starlette(
        debug=True,
        routes=[
            Route('/app', app_view),
        ],
        middleware=[
            Middleware(AuthenticationMiddleware, authenticators=[APIKeyAuthenticator(inmemory_user_provider)]),
            Middleware(ImpersonationMiddleware, user_provider=inmemory_user_provider, guard_fn=lambda c, u: False),
        ],
    )
    test_client = TestClient(app)
    response = test_client.get('/app?_impersonate=customer@localhost&apikey=root@localhost')
    assert response.json()['user_id'] == 'root@localhost'


def test_user_has_required_scope() -> None:
    class _User(User):
        def get_scopes(self) -> list:
            return ['auth:impersonate_others']

    user_provider = InMemoryProvider(
        {
            'impersonator@localhost': _User(),
            **inmemory_user_provider.user_map,
        }
    )

    app = Starlette(
        debug=True,
        routes=[
            Route('/app', app_view),
        ],
        middleware=[
            Middleware(AuthenticationMiddleware, authenticators=[APIKeyAuthenticator(user_provider)]),
            Middleware(ImpersonationMiddleware, user_provider=user_provider),
        ],
    )
    test_client = TestClient(app)
    response = test_client.get('/app?_impersonate=customer@localhost&apikey=impersonator@localhost')
    assert response.json()['user_id'] == 'customer@localhost'


def test_user_has_not_required_scope() -> None:
    class _User(User):
        def get_scopes(self) -> list:
            return []

    user_provider = InMemoryProvider(
        {
            'impersonator@localhost': _User(),
            **inmemory_user_provider.user_map,
        }
    )

    app = Starlette(
        debug=True,
        routes=[
            Route('/app', app_view),
        ],
        middleware=[
            Middleware(AuthenticationMiddleware, authenticators=[APIKeyAuthenticator(user_provider)]),
            Middleware(ImpersonationMiddleware, user_provider=user_provider),
        ],
    )
    test_client = TestClient(app)
    response = test_client.get('/app?_impersonate=customer@localhost&apikey=impersonator@localhost')
    assert response.json()['user_id'] == 'root@localhost'


def test_guard_fn_has_higher_precedence() -> None:
    class _User(User):
        def get_scopes(self) -> t.List[str]:
            return ['auth:impersonate_others']

    user_provider = InMemoryProvider({'impersonator@localhost': _User()})

    app = Starlette(
        debug=True,
        routes=[
            Route('/app', app_view),
        ],
        middleware=[
            Middleware(AuthenticationMiddleware, authenticators=[APIKeyAuthenticator(user_provider)]),
            Middleware(ImpersonationMiddleware, user_provider=user_provider, guard_fn=lambda c, u: False),
        ],
    )
    test_client = TestClient(app)
    response = test_client.get('/app?_impersonate=customer@localhost&apikey=impersonator@localhost')
    assert response.json()['user_id'] == 'root@localhost'


def test_helpers() -> None:
    def helpers_view(request: Request) -> JSONResponse:
        return JSONResponse(
            {
                'current_user': request.auth.user_id,
                'active': impersonation_is_active(request),
                'original_user': get_original_user(request).get_id(),
            }
        )

    app = Starlette(
        debug=True,
        routes=[
            Route('/app', helpers_view),
        ],
        middleware=[
            Middleware(AuthenticationMiddleware, authenticators=[APIKeyAuthenticator(inmemory_user_provider)]),
            Middleware(ImpersonationMiddleware, user_provider=inmemory_user_provider, guard_fn=lambda c, u: True),
        ],
    )
    test_client = TestClient(app)
    response = test_client.get('/app?_impersonate=customer@localhost&apikey=root@localhost')
    assert response.json()['current_user'] == 'customer@localhost'
    assert response.json()['active'] is True
    assert response.json()['original_user'] == 'root@localhost'

    response = test_client.get('/app?apikey=root@localhost')
    assert response.json()['current_user'] == 'root@localhost'
    assert response.json()['active'] is False
    assert response.json()['original_user'] == 'root@localhost'
