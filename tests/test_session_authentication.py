from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from imia import SESSION_HASH, SESSION_KEY, AuthenticationMiddleware, LoginManager, SessionAuthenticator
from tests.conftest import inmemory_user_provider, password_verifier


async def login_view(request: Request) -> RedirectResponse:
    form_data = await request.form()
    email = form_data.get('email')
    password = form_data.get('password')
    login_manager = LoginManager(inmemory_user_provider, password_verifier)
    user_token = await login_manager.login(request, email, password)
    if user_token:
        return RedirectResponse('/app')
    return RedirectResponse('/login?error=1')


async def app_view(request: Request) -> JSONResponse:
    return JSONResponse(
        {
            'is_authenticated': request.auth.is_authenticated,
            'user_id': request.auth.user_id,
            'user_name': request.auth.display_name,
        }
    )


def test_session_authentication() -> None:
    app = Starlette(
        debug=True,
        routes=[
            Route('/login', login_view, methods=['POST']),
            Route('/app', app_view, methods=['GET']),
        ],
        middleware=[
            Middleware(SessionMiddleware, secret_key='key!'),
            Middleware(
                AuthenticationMiddleware,
                authenticators=[
                    SessionAuthenticator(user_provider=inmemory_user_provider),
                ],
            ),
        ],
    )
    test_client = TestClient(app)
    test_client.post('/login', data={'email': 'root@localhost', 'password': 'pa$$word'})
    response = test_client.get('/app')
    assert response.json()['is_authenticated'] is True
    assert response.json()['user_id'] == 'root@localhost'
    assert response.json()['user_name'] == 'Root'


def test_session_authentication_with_missing_user() -> None:
    def change_user_view(request: Request) -> JSONResponse:
        request.session[SESSION_KEY] = 'otheruser@localhost'
        request.session[SESSION_HASH] = 'otheruser@localhost-hash'
        return JSONResponse({})

    app = Starlette(
        debug=True,
        routes=[
            Route('/login', login_view, methods=['POST']),
            Route('/change-user', change_user_view),
            Route('/app', app_view, methods=['GET']),
        ],
        middleware=[
            Middleware(SessionMiddleware, secret_key='key!'),
            Middleware(
                AuthenticationMiddleware,
                authenticators=[
                    SessionAuthenticator(user_provider=inmemory_user_provider),
                ],
            ),
        ],
    )
    test_client = TestClient(app)
    test_client.get('/change-user')  # monkey-patch session value
    response = test_client.get('/app')
    assert response.json()['is_authenticated'] is False
