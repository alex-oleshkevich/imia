"""
This example requires SQLAlchemy 1.4+ with aiosqlite installed

pip install sqlalchemy aiosqlite
"""
from dataclasses import dataclass

import os
import sqlalchemy as sa
import typing as t
from passlib.hash import pbkdf2_sha1
from sqlalchemy.ext.asyncio import create_async_engine
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from imia import APIKeyAuthenticator, AuthenticationMiddleware, LoginManager
from imia.ext.sqlalchemy import SQLAlchemyCoreUserProvider

DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite+aiosqlite:///:memory:')

engine = create_async_engine(DATABASE_URL)
metadata = sa.MetaData()

users_table = sa.Table(
    'users',
    metadata,
    sa.Column(sa.Integer, name='id', primary_key=True),
    sa.Column(sa.String, name='name'),
    sa.Column(sa.String, name='email', index=True),
    sa.Column(sa.String, name='password'),
    sa.Column(sa.String, name='api_token', index=True),
)


@dataclass
class User:
    """This is our user model. Any user model must implement UserLike protocol."""

    id: t.Optional[int] = None
    name: str = ""
    email: str = ""
    password: str = ""
    api_token: str = ""

    def get_display_name(self) -> str:
        return self.name

    def get_id(self) -> int:
        assert self.id
        return self.id

    def get_hashed_password(self) -> str:
        return self.password

    def get_scopes(self) -> list:
        return []


secret_key = 'key!'
"""For security!"""

user_provider = SQLAlchemyCoreUserProvider(engine, User, users_table)
"""The class that looks up for a user. you may provide your own for, eg. database user lookup"""

password_verifier = pbkdf2_sha1
"""Password checking tool. Password checkers must match PasswordVerifier protocol."""

login_manager = LoginManager(user_provider, password_verifier, secret_key)
"""This is the core class of login/logout flow"""


async def on_app_startup() -> None:
    async with engine.begin() as connection:
        await connection.run_sync(metadata.create_all)
        password_hash = pbkdf2_sha1.hash("password")
        stmt = users_table.insert(
            [
                {
                    'id': 1,
                    'name': "User One",
                    "email": "one@example.com",
                    'password': password_hash,
                    'api_token': "token1",
                },
                {
                    'id': 2,
                    'name': "User Two",
                    "email": "two@example.com",
                    'password': password_hash,
                    'api_token': "token2",
                },
                {
                    'id': 3,
                    'name': "User Three",
                    "email": "three@example.com",
                    'password': password_hash,
                    'api_token': "token3",
                },
            ]
        )
        await connection.execute(stmt)


async def on_app_shutdown() -> None:
    async with engine.begin() as connection:
        await connection.run_sync(metadata.drop_all)


def whoami_view(request: Request) -> JSONResponse:
    """
    GET http://127.0.0.1:7000/ - unauthenticated
    GET http://127.0.0.1:7000/?apikey=token1 - authenticate as User One
    GET http://127.0.0.1:7000/?apikey=token2 - authenticate as User Two
    GET http://127.0.0.1:7000/?apikey=token3 - authenticate as User Three
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
    on_startup=[on_app_startup],
    on_shutdown=[on_app_shutdown],
    middleware=[
        Middleware(AuthenticationMiddleware, authenticators=[APIKeyAuthenticator(user_provider)]),
    ],
)
