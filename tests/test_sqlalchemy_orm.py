import asyncio
import pytest
import sqlalchemy as sa
import typing as t
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from starlette.requests import HTTPConnection

from imia.ext.sqlalchemy import SQLAlchemyORMUserProvider

engine = create_async_engine('sqlite+aiosqlite:///:memory:')
session_maker = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
Base = declarative_base()


class _User(Base):
    """
    This is our user model.

    Any user model must implement UserLike protocol.
    """

    __tablename__ = 'sa_orm_users'

    id = sa.Column(sa.Integer, primary_key=True)
    name = sa.Column(sa.String(length=255), nullable=False)
    email = sa.Column(sa.String(length=255), nullable=False)
    password = sa.Column(sa.String(length=255), nullable=False)
    api_token = sa.Column(sa.String(length=255))

    def get_display_name(self) -> str:
        return self.name or ''

    def get_id(self) -> int:
        assert self.id
        return self.id

    def get_hashed_password(self) -> str:
        return self.password or ''

    def get_scopes(self) -> list:
        return []


@pytest.fixture(scope='session')
def event_loop() -> asyncio.AbstractEventLoop:
    return asyncio.get_event_loop()


@pytest.mark.asyncio
@pytest.fixture(autouse=True, scope='session')
async def create_tables() -> t.AsyncGenerator:
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with session_maker() as session:
        async with session.begin():
            session.add_all(
                [
                    _User(id=1, name="User One", email="one@example.com", password='password', api_token="token1"),
                    _User(id=2, name="User Two", email="two@example.com", password='password', api_token="token2"),
                    _User(id=3, name="User Three", email="three@example.com", password='password', api_token="token3"),
                ]
            )
            await session.flush()
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.mark.asyncio
async def test_sqlalchemy_orm_user_provider_find_by_id(http_connection: HTTPConnection) -> None:
    provider = SQLAlchemyORMUserProvider(session_maker, _User)
    user = await provider.find_by_id(http_connection, 2)
    assert isinstance(user, _User)
    assert user.id == 2

    assert await provider.find_by_id(http_connection, -1) is None


@pytest.mark.asyncio
async def test_sqlalchemy_orm_user_provider_find_by_username(http_connection: HTTPConnection) -> None:
    provider = SQLAlchemyORMUserProvider(session_maker, _User)
    user = await provider.find_by_username(http_connection, 'two@example.com')
    assert isinstance(user, _User)
    assert user.id == 2

    assert await provider.find_by_username(http_connection, 'unknown@example.com') is None


@pytest.mark.asyncio
async def test_sqlalchemy_orm_user_provider_find_by_token(http_connection: HTTPConnection) -> None:
    provider = SQLAlchemyORMUserProvider(session_maker, _User)
    user = await provider.find_by_token(http_connection, 'token2')
    assert isinstance(user, _User)
    assert user.id == 2

    assert await provider.find_by_token(http_connection, 'unknown_token') is None
