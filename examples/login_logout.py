import dataclasses
from dataclasses import dataclass

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.routing import Route

from imia import AuthenticationMiddleware, ImpersonationMiddleware, InMemoryProvider, LoginManager, SessionAuthenticator


@dataclass
class User:
    identifier: str = 'root@localhost'
    password: str = 'pa$$word'
    scopes: list[str] = dataclasses.field(default=list)

    def get_display_name(self):
        return 'User'

    def get_identifier(self):
        return self.identifier

    def get_hashed_password(self):
        return self.password

    def get_scopes(self):
        return self.scopes


class UnsafePasswordVerifier:
    def verify(self, plain: str, hashed: str) -> bool:
        return plain == hashed


secret_key = 'key!'
user_provider = InMemoryProvider({
    'root@localhost': User()
})

password_verifier = UnsafePasswordVerifier()

login_manager = LoginManager(user_provider, password_verifier, secret_key)


def index_view(request: Request) -> HTMLResponse:
    return HTMLResponse("""<a href="/login">Login</a> | <a href="/app">App</a>""")


async def login_view(request: Request):
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
    return HTMLResponse("""
    %s
    <form method="post">
    <label>email <input name="email" value="root@localhost"></label>
    <label>password <input name="password" type="password" value="pa$$word"></label>
    <button type="submit">submit</button>
    </form>
    """ % error)


async def logout_view(request: Request) -> RedirectResponse:
    if request.method == 'POST':
        login_manager.logout(request)
        return RedirectResponse('/login', status_code=302)
    return RedirectResponse('/app', status_code=302)


async def app_view(request: Request) -> HTMLResponse:
    user = request.auth.display_name
    return HTMLResponse(
        """
        Hi %s! This is protected app area.
        <form action="/logout" method="post">
        <button>logout</button>
        </form>
        """ % user
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
            AuthenticationMiddleware, authenticators=[SessionAuthenticator(user_provider)],
            on_failure='redirect', redirect_to='/login', exclude=[r'login', r'\/$']
        ),
    ],
)
