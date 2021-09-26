import asyncio
import pytest
import sqlalchemy as sa
import typing as t
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import DeclarativeMeta, declarative_base, sessionmaker

from imia.ext.sqlalchemy import SQLAlchemyORMUserProvider

engine = create_async_engine('sqlite+aiosqlite:///:memory:')
session_maker = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
Base: DeclarativeMeta = declarative_base()


class _User(Base):
    """This is our user model. Any user model must implement UserLike protocol."""

    __tablename__ = 'sa_orm_users'

    id = sa.Column(sa.Integer, primary_key=True)
    name = sa.Column(sa.String(length=255))
    email = sa.Column(sa.String(length=255))
    password = sa.Column(sa.String(length=255))
    api_token = sa.Column(sa.String(length=255))

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
async def test_sqlalchemy_orm_user_provider_find_by_id() -> None:
    provider = SQLAlchemyORMUserProvider(session_maker, _User)
    user = await provider.find_by_id(2)
    assert isinstance(user, _User)
    assert user.id == 2

    assert await provider.find_by_id(-1) is None


@pytest.mark.asyncio
async def test_sqlalchemy_orm_user_provider_find_by_username() -> None:
    provider = SQLAlchemyORMUserProvider(session_maker, _User)
    user = await provider.find_by_username('two@example.com')
    assert isinstance(user, _User)
    assert user.id == 2

    assert await provider.find_by_username('unknown@example.com') is None


@pytest.mark.asyncio
async def test_sqlalchemy_orm_user_provider_find_by_token() -> None:
    provider = SQLAlchemyORMUserProvider(session_maker, _User)
    user = await provider.find_by_token('token2')
    assert isinstance(user, _User)
    assert user.id == 2

    assert await provider.find_by_token('unknown_token') is None
