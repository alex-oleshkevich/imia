import dataclasses
from dataclasses import dataclass

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.routing import Route

from imia import AuthenticationMiddleware, ImpersonationMiddleware, InMemoryProvider, LoginManager


@dataclass
class User:
    identifier: str = 'root@localhost'
    password: str = 'pa$$word'
    scopes: list[str] = dataclasses.field(default=list)

    def get_display_name(self):
        return 'User'

    def get_identifier(self):
        return self.identifier

    def get_raw_password(self):
        return self.password

    def get_scopes(self):
        return self.scopes


class UnsafePasswordVerifier:
    def verify(self, plain: str, hashed: str) -> bool:
        return plain == hashed


user_provider = InMemoryProvider({
    'root@localhost': User()
})


def index_view(request: Request) -> HTMLResponse:
    return HTMLResponse('<a href"/login">Login</a>')


async def login_view(request: Request) -> RedirectResponse:
    form = await request.form()
    email = form['email']
    password = form['password']

    login_manager = LoginManager()
    user_token = await login_manager.login(request, email, password)
    if user_token:
        return RedirectResponse('/app')
    return RedirectResponse('/login?error=invalid_credentials')


async def logout_view(request: Request) -> RedirectResponse:
    login_manager = LoginManager()
    login_manager.logout(request)
    return RedirectResponse('/login')


async def app_view(request: Request) -> HTMLResponse:
    return HTMLResponse('This is protected app area.')


app = Starlette(
    debug=True,
    routes=[
        Route('/', index_view),
        Route('/login', login_view, methods=['get', 'post']),
        Route('/logout', login_view, methods=['post']),
        Route('/app', app_view),
    ],
    middleware=[
        Middleware(SessionMiddleware),
        Middleware(AuthenticationMiddleware),
        Middleware(ImpersonationMiddleware),
    ],
)
