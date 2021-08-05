import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from imia import APIKeyAuthenticator, AuthenticationError, AuthenticationMiddleware
from tests.conftest import inmemory_user_provider


async def app_view(request: Request):
    return JSONResponse(
        {
            'is_authenticated': request.auth.is_authenticated,
            'user_id': request.auth.user_id,
            'user_name': request.auth.display_name,
        }
    )


def test_middleware_ignores_url_patterns():
    app = Starlette(
        debug=True,
        routes=[
            Route('/app', app_view, methods=['GET']),
            Route('/app2', app_view, methods=['GET']),
        ],
        middleware=[
            Middleware(
                AuthenticationMiddleware,
                authenticators=[
                    APIKeyAuthenticator(users=inmemory_user_provider),
                ],
                on_failure='raise',
                exclude_patterns=[r'app2'],
            ),
        ],
    )
    test_client = TestClient(app)
    response = test_client.get('/app?apikey=root@localhost')
    assert response.json()['is_authenticated'] is True

    # the middleware must bypass this request
    response = test_client.get('/app2')
    assert response.json()['is_authenticated'] is False


def test_middleware_protects_only_specific_url_patterns():
    app = Starlette(
        debug=True,
        routes=[
            Route('/login', app_view, methods=['GET']),
            Route('/app', app_view, methods=['GET']),
            Route('/app2', app_view, methods=['GET']),
        ],
        middleware=[
            Middleware(
                AuthenticationMiddleware,
                authenticators=[
                    APIKeyAuthenticator(users=inmemory_user_provider),
                ],
                on_failure='raise',
                include_patterns=['/app2'],
            ),
        ],
    )
    test_client = TestClient(app)

    # the middleware must bypass this request
    response = test_client.get('/app?apikey=root@localhost')
    assert response.json()['is_authenticated'] is False

    # the middleware must bypass this request
    response = test_client.get('/app2?apikey=root@localhost')
    assert response.json()['is_authenticated'] is True

    # the middleware must bypass this request
    response = test_client.get('/login')
    assert response.json()['is_authenticated'] is False


def test_middleware_mode_raises():
    app = Starlette(
        debug=True,
        routes=[
            Route('/app', app_view, methods=['GET']),
        ],
        middleware=[
            Middleware(
                AuthenticationMiddleware,
                authenticators=[
                    APIKeyAuthenticator(users=inmemory_user_provider),
                ],
                on_failure='raise',
            ),
        ],
    )
    test_client = TestClient(app)
    response = test_client.get('/app?apikey=root@localhost')
    assert response.json()['is_authenticated'] is True

    with pytest.raises(AuthenticationError) as ex:
        test_client.get('/app?apikey=invalid@localhost')
    assert str(ex.value) == 'Could not authenticate request.'


def test_middleware_redirect():
    app = Starlette(
        debug=True,
        routes=[
            Route('/app', app_view, methods=['GET']),
        ],
        middleware=[
            Middleware(
                AuthenticationMiddleware,
                authenticators=[
                    APIKeyAuthenticator(users=inmemory_user_provider),
                ],
                on_failure='redirect',
                redirect_to='/login',
                exclude_patterns=['login'],
            ),
        ],
    )
    test_client = TestClient(app)
    response = test_client.get('/app?apikey=root@localhost')
    assert response.json()['is_authenticated'] is True

    response = test_client.get('/app?apikey=invalid@localhost', allow_redirects=False)
    assert response.status_code == 307
    assert response.headers['location'] == '/login'


def test_middleware_redirect_requires_url():
    with pytest.raises(ValueError) as ex:
        app = Starlette(
            debug=True,
            routes=[
                Route('/app', app_view, methods=['GET']),
            ],
            middleware=[
                Middleware(
                    AuthenticationMiddleware,
                    authenticators=[
                        APIKeyAuthenticator(users=inmemory_user_provider),
                    ],
                    on_failure='redirect',
                    redirect_to=None,
                ),
            ],
        )
        test_client = TestClient(app)
        test_client.get('/app?apikey=invalid@localhost', allow_redirects=False)
    assert str(ex.value) == (
        'redirect_to attribute of AuthenticationMiddleware cannot be None ' 'if on_failure is set to "redirect".'
    )


def test_middleware_does_nothing():
    app = Starlette(
        debug=True,
        routes=[
            Route('/app', app_view, methods=['GET']),
        ],
        middleware=[
            Middleware(
                AuthenticationMiddleware,
                authenticators=[
                    APIKeyAuthenticator(users=inmemory_user_provider),
                ],
                on_failure='do_nothing',
            ),
        ],
    )
    test_client = TestClient(app)
    response = test_client.get('/app?apikey=root@localhost')
    assert response.json()['is_authenticated'] is True

    response = test_client.get('/app?apikey=invalid@localhost')
    assert response.json()['is_authenticated'] is False


def test_middleware_unsupported_action():
    app = Starlette(
        debug=True,
        routes=[
            Route('/app', app_view, methods=['GET']),
        ],
        middleware=[
            Middleware(
                AuthenticationMiddleware,
                authenticators=[
                    APIKeyAuthenticator(users=inmemory_user_provider),
                ],
                on_failure='unknown',
            ),
        ],
    )
    test_client = TestClient(app)
    response = test_client.get('/app?apikey=root@localhost')
    assert response.json()['is_authenticated'] is True

    with pytest.raises(ValueError) as ex:
        response = test_client.get('/app?apikey=invalid@localhost')
        assert response.json()['is_authenticated'] is False
    assert str(ex.value) == ('Unsupported action passed to AuthenticationMiddleware via on_failure argument: unknown.')


def test_middleware_raises_if_both_include_and_exclude_patterns_passed():
    with pytest.raises(ValueError) as ex:
        Starlette(
            debug=True,
            routes=[
                Route('/app', app_view, methods=['GET']),
            ],
            middleware=[
                Middleware(
                    AuthenticationMiddleware,
                    authenticators=[
                        APIKeyAuthenticator(users=inmemory_user_provider),
                    ],
                    on_failure='raise',
                    include_patterns=[],
                    exclude_patterns=[],
                ),
            ],
        )
    assert str(ex.value) == '"exclude_patterns" and "include_patterns" are mutially exclusive.'
