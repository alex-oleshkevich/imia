import dataclasses
from dataclasses import dataclass

from passlib.hash import pbkdf2_sha1
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from imia import APIKeyAuthenticator, AuthenticationMiddleware, ImpersonationMiddleware, InMemoryProvider, LoginManager


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

user_provider = InMemoryProvider(
    {
        'root@localhost': User(scopes=['auth:impersonate_others']),
        'customer@localhost': User(identifier='customer@localhost'),
    }
)
"""The class that looks up for a user. you may provide your own for, eg. database user lookup"""

password_verifier = pbkdf2_sha1
"""Password checking tool. Password checkers must match PasswordVerifier protocol."""

login_manager = LoginManager(user_provider, password_verifier, secret_key)
"""This is the core class of login/logout flow"""


def whoami_view(request: Request) -> JSONResponse:
    """
    GET http://127.0.0.1:7000/ - unauthenticated
    GET http://127.0.0.1:7000/?apikey=root@localhost - no impersonation
    GET http://127.0.0.1:7000/?apikey=root@localhost&_impersonate=customer@localhost - impersonate customer@localhost
    """
    return JSONResponse(
        {
            'id': request.auth.user_id,
            'name': request.auth.display_name,
        }
    )


app = Starlette(
    debug=True,
    routes=[
        Route('/', whoami_view),
    ],
    middleware=[
        Middleware(AuthenticationMiddleware, authenticators=[APIKeyAuthenticator(user_provider)]),
        Middleware(ImpersonationMiddleware, user_provider=user_provider),
    ],
)
