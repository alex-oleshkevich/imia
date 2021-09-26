"""
This example requires SQLAlchemy 1.4+ with aiosqlite installed

pip install sqlalchemy aiosqlite
"""
import os
import sqlalchemy as sa
from passlib.hash import pbkdf2_sha1
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import DeclarativeMeta, declarative_base, sessionmaker
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from imia import APIKeyAuthenticator, AuthenticationMiddleware, LoginManager
from imia.ext.sqlalchemy import SQLAlchemyORMUserProvider

DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite+aiosqlite:///:memory:')

engine = create_async_engine(DATABASE_URL)
async_session = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
Base: DeclarativeMeta = declarative_base()


class User(Base):
    """This is our user model. Any user model must implement UserLike protocol."""

    __tablename__ = 'users'

    id = sa.Column(sa.Integer, primary_key=True)
    name = sa.Column(sa.String)
    email = sa.Column(sa.String)
    password = sa.Column(sa.String)
    api_token = sa.Column(sa.String)

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

user_provider = SQLAlchemyORMUserProvider(async_session, User)
"""The class that looks up for a user. you may provide your own for, eg. database user lookup"""

password_verifier = pbkdf2_sha1
"""Password checking tool. Password checkers must match PasswordVerifier protocol."""

login_manager = LoginManager(user_provider, password_verifier, secret_key)
"""This is the core class of login/logout flow"""


async def on_app_startup() -> None:
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with async_session() as session:
        async with session.begin():
            password_hash = pbkdf2_sha1.hash("password")
            session.add_all(
                [
                    User(id=1, name="User One", email="one@example.com", password=password_hash, api_token="token1"),
                    User(id=2, name="User Two", email="two@example.com", password=password_hash, api_token="token2"),
                    User(
                        id=3, name="User Three", email="three@example.com", password=password_hash, api_token="token3"
                    ),
                ]
            )
            await session.flush()


async def on_app_shutdown() -> None:
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)


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
