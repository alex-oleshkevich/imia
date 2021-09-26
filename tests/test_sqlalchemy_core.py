from dataclasses import dataclass

import asyncio
import pytest
import sqlalchemy as sa
import typing as t
from sqlalchemy.ext.asyncio import create_async_engine

from imia.ext.sqlalchemy import SQLAlchemyCoreUserProvider

metadata = sa.MetaData()
users_table = sa.Table(
    'sa_core_users',
    metadata,
    sa.Column(sa.Integer, name='id', primary_key=True),
    sa.Column(sa.String(length=255), name='email'),
    sa.Column(sa.String(length=255), name='api_token'),
)

engine = create_async_engine('sqlite+aiosqlite:///:memory:')


@dataclass
class _User:
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


@pytest.fixture(scope='session')
def event_loop() -> asyncio.AbstractEventLoop:
    return asyncio.get_event_loop()


@pytest.mark.asyncio
@pytest.fixture(autouse=True, scope='session')
async def create_tables() -> t.AsyncGenerator:
    async with engine.begin() as connection:
        await connection.run_sync(metadata.create_all)
        stmt = users_table.insert(
            [
                {
                    'id': 1,
                    "email": "one@example.com",
                    'api_token': "token1",
                },
                {
                    'id': 2,
                    "email": "two@example.com",
                    'api_token': "token2",
                },
                {
                    'id': 3,
                    "email": "three@example.com",
                    'api_token': "token3",
                },
            ]
        )
        await connection.execute(stmt)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(metadata.drop_all)


@pytest.mark.asyncio
async def test_sqlalchemy_core_user_provider_find_by_id() -> None:
    provider = SQLAlchemyCoreUserProvider(engine, _User, users_table)
    user = await provider.find_by_id(2)
    assert isinstance(user, _User)
    assert user.id == 2

    assert await provider.find_by_id(-1) is None


@pytest.mark.asyncio
async def test_sqlalchemy_core_user_provider_find_by_username() -> None:
    provider = SQLAlchemyCoreUserProvider(engine, _User, users_table)
    user = await provider.find_by_username('two@example.com')
    assert isinstance(user, _User)
    assert user.id == 2

    assert await provider.find_by_username('unknown@example.com') is None


@pytest.mark.asyncio
async def test_sqlalchemy_core_user_provider_find_by_token() -> None:
    provider = SQLAlchemyCoreUserProvider(engine, _User, users_table)
    user = await provider.find_by_token('token2')
    assert isinstance(user, _User)
    assert user.id == 2

    assert await provider.find_by_token('unknown_token') is None
