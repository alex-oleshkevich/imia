from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from imia import AuthenticationMiddleware, BasicAuthenticator, LoginManager, SessionAuthenticator
from tests.conftest import inmemory_user_provider, password_verifier


async def login_view(request: Request):
    form_data = await request.form()
    email = form_data.get('email')
    password = form_data.get('password')
    login_manager = LoginManager(inmemory_user_provider, password_verifier)
    user_token = await login_manager.login(request, email, password)
    if user_token:
        return RedirectResponse('/app')
    return RedirectResponse('/login?error=1')


async def app_view(request: Request):
    return JSONResponse({
        'is_authenticated': request.auth.is_authenticated,
        'user_id': request.auth.identity,
        'user_name': request.auth.display_name,
    })


def test_basic_authentication():
    """WWW-Basic authentication uses user data from URL to obtain user ID."""
    app = Starlette(debug=True, routes=[
        Route('/app', app_view, methods=['GET']),
    ], middleware=[
        Middleware(AuthenticationMiddleware, authenticators=[
            BasicAuthenticator(users=inmemory_user_provider, password_verifier=password_verifier),
        ]),
    ])
    test_client = TestClient(app)
    response = test_client.get('/app', auth=('root@localhost', 'pa$$word'))
    assert response.json()['is_authenticated'] is True
    assert response.json()['user_id'] == 'root@localhost'
    assert response.json()['user_name'] == 'Root'


def test_basic_authentication_with_invalid_password():
    app = Starlette(debug=True, routes=[
        Route('/app', app_view, methods=['GET']),
    ], middleware=[
        Middleware(AuthenticationMiddleware, authenticators=[
            BasicAuthenticator(users=inmemory_user_provider, password_verifier=password_verifier),
        ]),
    ])
    test_client = TestClient(app)
    response = test_client.get('/app', auth=('root@localhost', 'invaild'))
    assert response.json()['is_authenticated'] is False


def test_basic_authentication_with_empty_password():
    app = Starlette(debug=True, routes=[
        Route('/app', app_view, methods=['GET']),
    ], middleware=[
        Middleware(AuthenticationMiddleware, authenticators=[
            BasicAuthenticator(users=inmemory_user_provider, password_verifier=password_verifier),
        ]),
    ])
    test_client = TestClient(app)
    response = test_client.get('/app', auth=('root@localhost', ''))
    assert response.json()['is_authenticated'] is False


def test_basic_authentication_without_credentials():
    app = Starlette(debug=True, routes=[
        Route('/app', app_view, methods=['GET']),
    ], middleware=[
        Middleware(AuthenticationMiddleware, authenticators=[
            BasicAuthenticator(users=inmemory_user_provider, password_verifier=password_verifier),
        ]),
    ])
    test_client = TestClient(app)
    response = test_client.get('/app')
    assert response.json()['is_authenticated'] is False


def test_basic_authentication_with_invalid_user():
    app = Starlette(debug=True, routes=[
        Route('/app', app_view, methods=['GET']),
    ], middleware=[
        Middleware(AuthenticationMiddleware, authenticators=[
            BasicAuthenticator(users=inmemory_user_provider, password_verifier=password_verifier),
        ]),
    ])
    test_client = TestClient(app)
    response = test_client.get('/app', auth=('missing@localhost', 'password'))
    assert response.json()['is_authenticated'] is False


def test_token_authentication(): ...


def test_bearer_authentication(): ...
