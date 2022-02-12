import dataclasses
from dataclasses import dataclass

from passlib.hash import pbkdf2_sha1
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

from imia import AuthenticationMiddleware, InMemoryProvider, LoginManager, SessionAuthenticator


@dataclass
class User:
    """
    This is our user model.

    Any user model must implement UserLike protocol.
    """

    identifier: str = 'root@localhost'
    password: str = '$pbkdf2$131000$xfhfaw1hrNU6ByAkBKA0Zg$qT.ZZYscSAUS4Btk/Q2rkAZQc5E'  # pa$$word
    scopes: list[str] = dataclasses.field(default_factory=list)

    def get_display_name(self) -> str:
        return 'User'

    def get_id(self) -> str:
        return self.identifier

    def get_hashed_password(self) -> str:
        return self.password

    def get_scopes(self) -> list:
        return self.scopes


secret_key = 'key!'
"""For security!"""

user_provider = InMemoryProvider({'root@localhost': User()})
"""The class that looks up for a user. you may provide your own for, eg. database user lookup"""

password_verifier = pbkdf2_sha1
"""Password checking tool. Password checkers must match PasswordVerifier protocol."""

login_manager = LoginManager(user_provider, password_verifier, secret_key)
"""This is the core class of login/logout flow"""


def index_view(request: Request) -> HTMLResponse:
    """Display welcome page."""
    return HTMLResponse("""<a href="/login">Login</a> | <a href="/app">App</a>""")


async def login_view(request: Request) -> Response:
    """Display login page  and handle login POST request."""
    error = ''
    if 'error' in request.query_params:
        error = '<span style="color:red">invalid credentials</span>'
    if request.method == 'POST':
        form = await request.form()
        email = form['email']
        password = form['password']

        user_token = await login_manager.login(request, email, password)
        if user_token:
            return RedirectResponse('/app', status_code=302)
        return RedirectResponse('/login?error=invalid_credentials', status_code=302)
    return HTMLResponse(
        """
    %s
    <form method="post">
    <label>email <input name="email" value="root@localhost"></label>
    <label>password <input name="password" type="password" value="pa$$word"></label>
    <button type="submit">submit</button>
    </form>
    """
        % error
    )


async def logout_view(request: Request) -> RedirectResponse:
    """Handle logout request."""
    if request.method == 'POST':
        await login_manager.logout(request)
        return RedirectResponse('/login', status_code=302)
    return RedirectResponse('/app', status_code=302)


async def app_view(request: Request) -> HTMLResponse:
    """
    This is our protected area.

    Only authorized users allowed.
    """
    user = request.auth.display_name
    return HTMLResponse(
        """
        Hi %s! This is protected app area.
        <form action="/logout" method="post">
        <button>logout</button>
        </form>
        """
        % user
    )


app = Starlette(
    debug=True,
    routes=[
        Route('/', index_view),
        Route('/login', login_view, methods=['GET', 'POST']),
        Route('/logout', logout_view, methods=['POST']),
        Route('/app', app_view),
    ],
    middleware=[
        Middleware(SessionMiddleware, secret_key=secret_key),
        Middleware(
            AuthenticationMiddleware,
            authenticators=[SessionAuthenticator(user_provider)],
            on_failure='redirect',
            redirect_to='/login',
            include_patterns=[r'\/app']
            # protect /app path
        ),
    ],
)
