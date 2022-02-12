import dataclasses
from dataclasses import dataclass

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from imia import AuthenticationMiddleware, BearerAuthenticator, InMemoryProvider


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

user_provider = InMemoryProvider({'root@localhost': User(scopes=['auth:impersonate_others'])})
"""The class that looks up for a user. you may provide your own for, eg. database user lookup"""


def whoami_view(request: Request) -> JSONResponse:
    """
    curl -H 'Authorization: Bearer root@localhost'  http://localhost:7000/

    token, id and email is the same for this example and equals to
    "root@localhost"
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
        Middleware(AuthenticationMiddleware, authenticators=[BearerAuthenticator(user_provider)]),
    ],
)
