from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from imia import APIKeyAuthenticator, AuthenticationMiddleware, TokenAuthenticator
from tests.conftest import inmemory_user_provider


async def app_view(request: Request):
    return JSONResponse(
        {
            'is_authenticated': request.auth.is_authenticated,
            'user_id': request.auth.user_id,
            'user_name': request.auth.display_name,
        }
    )


def test_authenticates_successfully():
    app = Starlette(
        debug=True,
        routes=[
            Route('/app', app_view, methods=['GET']),
        ],
        middleware=[
            Middleware(
                AuthenticationMiddleware,
                authenticators=[
                    APIKeyAuthenticator(user_provider=inmemory_user_provider),
                    TokenAuthenticator(user_provider=inmemory_user_provider, token_name='Token'),
                ],
            ),
        ],
    )
    test_client = TestClient(app)
    response = test_client.get('/app', headers={'authorization': 'Token root@localhost'})
    assert response.json()['is_authenticated'] is True

    response = test_client.get('/app?apikey=root@localhost')
    assert response.json()['is_authenticated'] is True


def test_not_authenticates():
    app = Starlette(
        debug=True,
        routes=[
            Route('/app', app_view, methods=['GET']),
        ],
        middleware=[
            Middleware(
                AuthenticationMiddleware,
                authenticators=[
                    APIKeyAuthenticator(user_provider=inmemory_user_provider),
                    TokenAuthenticator(user_provider=inmemory_user_provider, token_name='Token'),
                ],
            ),
        ],
    )
    test_client = TestClient(app)
    response = test_client.get('/app', headers={'authorization': 'Token invalid@localhost'})
    assert response.json()['is_authenticated'] is False

    response = test_client.get('/app?apikey=invalid@localhost')
    assert response.json()['is_authenticated'] is False
