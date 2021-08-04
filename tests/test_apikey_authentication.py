from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from imia import APIKeyAuthenticator, AuthenticationMiddleware, BasicAuthenticator
from tests.conftest import inmemory_user_provider, password_verifier


async def app_view(request: Request):
    return JSONResponse({
        'is_authenticated': request.auth.is_authenticated,
        'user_id': request.auth.identity,
        'user_name': request.auth.display_name,
    })


def test_apikey_authentication():
    app = Starlette(debug=True, routes=[
        Route('/app', app_view, methods=['GET']),
    ], middleware=[
        Middleware(AuthenticationMiddleware, authenticators=[
            APIKeyAuthenticator(users=inmemory_user_provider),
        ]),
    ])
    test_client = TestClient(app)
    response = test_client.get('/app?apikey=root@localhost')
    assert response.json()['is_authenticated'] is True
    assert response.json()['user_id'] == 'root@localhost'
    assert response.json()['user_name'] == 'Root'


def test_apikey_authentication_with_invalid_user():
    app = Starlette(debug=True, routes=[
        Route('/app', app_view, methods=['GET']),
    ], middleware=[
        Middleware(AuthenticationMiddleware, authenticators=[
            APIKeyAuthenticator(users=inmemory_user_provider),
        ]),
    ])
    test_client = TestClient(app)
    response = test_client.get('/app?apikey=invalid@localhost')
    assert response.json()['is_authenticated'] is False

    response = test_client.get('/app', headers={'X-API-Key': 'invalid@localhost'})
    assert response.json()['is_authenticated'] is False


def test_apikey_authentication_using_header():
    app = Starlette(debug=True, routes=[
        Route('/app', app_view, methods=['GET']),
    ], middleware=[
        Middleware(AuthenticationMiddleware, authenticators=[
            APIKeyAuthenticator(users=inmemory_user_provider),
        ]),
    ])
    test_client = TestClient(app)
    response = test_client.get('/app', headers={'X-API-Key': 'root@localhost'})
    assert response.json()['is_authenticated'] is True
    assert response.json()['user_id'] == 'root@localhost'
    assert response.json()['user_name'] == 'Root'


def test_apikey_query_params_have_higher_precedense():
    app = Starlette(debug=True, routes=[
        Route('/app', app_view, methods=['GET']),
    ], middleware=[
        Middleware(AuthenticationMiddleware, authenticators=[
            APIKeyAuthenticator(users=inmemory_user_provider),
        ]),
    ])
    test_client = TestClient(app)
    response = test_client.get('/app?apikey=root@localhost', headers={'X-API-Key': 'invalid@localhost'})
    assert response.json()['is_authenticated'] is True


def test_apikey_with_missing_token():
    app = Starlette(debug=True, routes=[
        Route('/app', app_view, methods=['GET']),
    ], middleware=[
        Middleware(AuthenticationMiddleware, authenticators=[
            APIKeyAuthenticator(users=inmemory_user_provider),
        ]),
    ])
    test_client = TestClient(app)
    response = test_client.get('/app', headers={'X-API-Key': ''})
    assert response.json()['is_authenticated'] is False

    response = test_client.get('/app?apikey=')
    assert response.json()['is_authenticated'] is False

    response = test_client.get('/app')
    assert response.json()['is_authenticated'] is False
