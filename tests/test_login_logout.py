from dataclasses import dataclass

import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse
from starlette.routing import Route
from starlette.testclient import TestClient
from starsessions import InMemoryBackend, SessionMiddleware as StarSessionMiddleware

from imia import get_session_auth_id, login_user, LoginManager
from tests.conftest import inmemory_user_provider, password_verifier, User


@dataclass
class Attacker(User):
    password = 'hackit'


def index_view(request: Request):
    # empty sessions are deleted
    request.session['example'] = 'value'
    return JSONResponse({})


async def login_view(request: Request):
    form_data = await request.form()
    email = form_data.get('email')
    password = form_data.get('password')
    login_manager = LoginManager(inmemory_user_provider, password_verifier)
    user_token = await login_manager.login(request, email, password)
    if user_token:
        return RedirectResponse('/app')
    return RedirectResponse('/login?error=1')


async def logout_view(request: Request):
    login_manager = LoginManager(inmemory_user_provider, password_verifier)
    await login_manager.logout(request)
    return RedirectResponse('/login')


async def app_view(request: Request):
    return JSONResponse({'session_auth_id': get_session_auth_id(request)})


async def set_user_view(request: Request):
    """This view forcibly sets user.."""
    await login_user(request, User(), '')
    return JSONResponse({})


async def set_attacker_view(request: Request):
    """This view forcibly sets Attacker user that has same ID but different password."""
    await login_user(request, Attacker(), '')
    return JSONResponse({})


async def session_view(request: Request):
    return JSONResponse(dict(request.session))


app = Starlette(
    debug=True,
    routes=[
        Route('/', index_view),
        Route('/login', login_view, methods=['POST']),
        Route('/logout', logout_view, methods=['POST']),
        Route('/app', app_view),
        Route('/attack', set_attacker_view),
        Route('/user', set_user_view),
        Route('/session', session_view),
    ],
    middleware=[
        Middleware(SessionMiddleware, secret_key='key!'),
    ],
)

app2 = Starlette(
    debug=True,
    routes=[
        Route('/', index_view),
        Route('/login', login_view, methods=['POST']),
        Route('/logout', logout_view, methods=['POST']),
        Route('/app', app_view),
        Route('/attack', set_attacker_view),
        Route('/user', set_user_view),
        Route('/session', session_view),
    ],
    middleware=[
        Middleware(StarSessionMiddleware, secret_key='key!', autoload=True, backend=InMemoryBackend()),
    ],
)


@pytest.mark.parametrize('app', [app, app2])
def test_login(app):
    test_client = TestClient(app)
    response = test_client.post('/login', data={'email': 'root@localhost', 'password': 'pa$$word'})
    assert response.status_code == 307
    assert response.headers['location'] == '/app'
    response = test_client.get('/app')
    assert response.json().get('session_auth_id') == 'root@localhost'


@pytest.mark.parametrize('app', [app, app2])
def test_login_with_invalid_credentials(app):
    test_client = TestClient(app)
    response = test_client.post('/login', data={'email': 'root@localhost', 'password': 'invalid'})
    assert response.status_code == 307
    assert response.headers['location'] == '/login?error=1'
    response = test_client.get('/app')
    assert response.json().get('session_auth_id') is None


@pytest.mark.parametrize('app', [app, app2])
def test_logout(app):
    test_client = TestClient(app)
    test_client.post('/login', data={'email': 'root@localhost', 'password': 'invalid'})
    response = test_client.post('/logout')
    assert response.status_code == 307
    assert response.headers['location'] == '/login'

    response = test_client.get('/app')
    assert response.json().get('session_auth_id') is None


@pytest.mark.parametrize('app', [app, app2])
def test_regenerates_session_id(app):
    test_client = TestClient(app)
    response = test_client.get('/')
    session_id = response.cookies['session']
    response = test_client.get('/')
    assert session_id == response.cookies['session']

    test_client.post('/login', data={'email': 'root@localhost', 'password': 'pa$$word'})
    response = test_client.get('/')
    assert session_id != response.cookies['session']


@pytest.mark.parametrize('app', [app, app2])
def test_keep_session_data_for_user(app):
    test_client = TestClient(app)
    test_client.get('/')  # write some data to session
    test_client.get('/user')  # set user
    response = test_client.get('/session')  # read session contents
    assert 'example' in response.json()
    assert response.json().get('_auth_user_id') == 'root@localhost'

    # now login real account owner. we must detect that this is a different user and clear session
    test_client.post('/login', data={'email': 'root@localhost', 'password': 'pa$$word'})
    response = test_client.get('/session')  # read session contents
    assert 'example' in response.json()


@pytest.mark.parametrize('app', [app, app2])
def test_clears_session_if_reused_from_another_user(app):
    test_client = TestClient(app)
    test_client.get('/')  # write some data to session
    test_client.get('/attack')  # set attacker user
    response = test_client.get('/session')  # read session contents
    assert 'example' in response.json()
    assert response.json().get('_auth_user_id') == 'root@localhost'

    # now login real account owner. we must detect that this is a different user and clear session
    test_client.post('/login', data={'email': 'root@localhost', 'password': 'pa$$word'})
    response = test_client.get('/session')  # read session contents
    assert 'example' not in response.json()
