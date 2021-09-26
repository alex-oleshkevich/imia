import sqlalchemy as sa
import typing as t
from sqlalchemy import select
from sqlalchemy.engine import Result
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, AsyncSession
from sqlalchemy.orm import DeclarativeMeta, sessionmaker

from imia import UserLike, UserProvider


class SQLAlchemyCoreUserProvider(UserProvider):
    def __init__(
        self,
        engine: AsyncEngine,
        user_model: type,
        identity_table: sa.Table,
        identity_column: str = 'id',
        username_column: str = 'email',
        api_token_column: str = 'api_token',
    ) -> None:
        self._engine = engine
        self._user_model = user_model
        self._identity_table = identity_table
        self._identity_column = identity_column
        self._username_column = username_column
        self._api_token_column = api_token_column

    async def find_by_id(self, identifier: t.Any) -> t.Optional[UserLike]:
        return await self._fetch_user_by_column(self._identity_column, identifier)

    async def find_by_username(self, username_or_email: str) -> t.Optional[UserLike]:
        return await self._fetch_user_by_column(self._username_column, username_or_email)

    async def find_by_token(self, token: str) -> t.Optional[UserLike]:
        return await self._fetch_user_by_column(self._api_token_column, token)

    async def _fetch_user_by_column(self, column: str, value: t.Any) -> t.Optional[UserLike]:
        column = self._identity_table.columns[column]
        stmt = select(self._identity_table).where(column == value)
        async with self._engine.begin() as connection:  # type: AsyncConnection
            result: Result = await connection.execute(stmt)
        row = result.one_or_none()
        if row:
            return self._user_model(**row)
        return None


class SQLAlchemyORMUserProvider(UserProvider):
    def __init__(
        self,
        session_maker: sessionmaker,
        user_model: DeclarativeMeta,
        identity_column: str = 'id',
        username_column: str = 'email',
        api_token_column: str = 'api_token',
    ) -> None:
        self._session_maker = session_maker
        self._user_model = user_model
        self._identity_column = identity_column
        self._username_column = username_column
        self._api_token_column = api_token_column

    async def find_by_id(self, identifier: t.Any) -> t.Optional[UserLike]:
        return await self._fetch_user_by_column(self._identity_column, identifier)

    async def find_by_username(self, username_or_email: str) -> t.Optional[UserLike]:
        return await self._fetch_user_by_column(self._username_column, username_or_email)

    async def find_by_token(self, token: str) -> t.Optional[UserLike]:
        return await self._fetch_user_by_column(self._api_token_column, token)

    async def _fetch_user_by_column(self, column: str, value: t.Any) -> t.Optional[UserLike]:
        column = self._user_model.__table__.columns[column]
        stmt = select(self._user_model).where(column == value)
        async with self._session_maker() as session:  # type: AsyncSession
            result: Result = await session.execute(stmt)
        return result.scalar_one_or_none()
