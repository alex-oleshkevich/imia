# User providers

In the previous [section](userlike_protocol.md) we mentioned that library has no information about how your user model
looks like. Similarly to that, the library does not know about the underlying database (or other data storage). It may
be a SQL database, MongoDB, or a flat-file storage. In order to make this library work with any (really any) database we
introduce concept of _user providers_. A user provider is a class with a set of known methods that will be a bridge
between the library and your database.

## UserProvider interface

Various components from Imia will call the following methods:

* `find_by_id(identifier: typing.Any) -> UserLike` - the function loads user from the data source by ID
* `find_by_username(username_or_email: str) -> UserLike` - the function loads user from the data source by username or
  email.
* `find_by_token(token: str) -> UserLike` - the function loads user from the data source by API key or API token.

## Example user provider

Let's implement a basic user provider that uses a local variable as a user storage.
> Note, this is for demo purpose, do not use in-memory storages in production!

```python
import typing as t

from imia import UserProvider, UserLike


class User:
    """A class that implements methods from UserLike protocol. We will omit them in this example."""
    ...


# this is the user storage
_users: list[User] = []


class MyUserProvider(UserProvider):
    """An example user providers that stores users in a local variable."""

    async def find_by_id(self, identifier: t.Any) -> t.Optional[UserLike]:
        """Load user by user ID."""
        for user in _users:
            if user.id == identifier:
                return user

    async def find_by_username(self, username_or_email: str) -> t.Optional[UserLike]:
        """Load user by username or email."""
        for user in _users:
            if user.email == username_or_email:
                return user

    async def find_by_token(self, token: str) -> t.Optional[UserLike]:
        """Load user by token."""
        for user in _users:
            if user.api_token == token:
                return user
```

## Built-in user providers

We maintain several built-in user providers to save your time.

### InMemoryUserProvider

An in-memory user storage (much like the one from the example above). We suggest using it in unit-tests only or in
application that have a hardcoded list of users.

```python
from imia import InMemoryProvider

user_provider = InMemoryProvider({
    'user1': User(id=user1),
    'user2': User(id=user2),
}) 
```

### SQLAlchemyCoreUserProvider

> Requires sqlalchemy 1.4+ plus async driver (like asyncpg or aiosqlite).

Since version 1.4 SQLAlchemy has a native support of async/await syntax. This provider makes use of asynchronous
capabilities of the SQLAlchemy Core.

The provider must be configured first and here is the list of options:

| Argument | Default | Type | Description | 
|----------|------|---------|----| 
| engine | required| [AsyncEngine](https://docs.sqlalchemy.org/en/14/orm/extensions/asyncio.html#sqlalchemy.ext.asyncio.AsyncEngine)| An engine (bind) to use for querying.| 
| user_model | required| type | A UserLike class. The provider will instantiate it with keyword arguments from the query row. |
| identity_table | required | sqlalchemy.Table| A SQLAlchemy table that stores user information.  |
| identity_column |  'id' | str | A table column with user ID.|
| username_column |  'email' | str | A table column with username or email.|
| api_token_column |  'api_token' | str | A table column with API token (or API key).|

Example usage:

```python
from dataclasses import dataclass

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from imia.ext.sqlalchemy import SQLAlchemyCoreUserProvider

metadata = sa.MetaData()
users_table = sa.Table(
    'users', metadata,
    sa.Column(sa.Integer, name='id', primary_key=True),
    sa.Column(sa.String, name='email'),
)

engine = create_async_engine('sqlite+aiosqlite:///:memory:')


@dataclass
class User:
    id: str
    email: str


user_provider = SQLAlchemyCoreUserProvider(engine, User, users_table)
```

See full example in [examples/sqlalchemy_core.py](../examples/sqlalchemy_core.py)

### SQLAlchemyORMUserProvider

> Requires sqlalchemy 1.4+ plus async driver (like asyncpg or aiosqlite).

This provider is similar to [SQLAlchemyCoreUserProvider](#sqlalchemycoreuserprovider) but works with Session.

The provider must be configured first and here is the list of options:

| Argument | Default | Type | Description | 
|----------|------|---------|----| 
| session_maker | required| [sessionmaker](https://docs.sqlalchemy.org/en/14/orm/session_api.html#sqlalchemy.orm.sessionmaker)| An session maker instance.| 
| user_model | required| object | A UserLike class. |
| identity_column |  'id' | str | A table column that contains user ID.|
| username_column |  'email' | str | A table column that contains username or email.|
| api_token_column |  'api_token' | str | A table column that contains API token (or API key).|

Example usage:

```python
import sqlalchemy as sa
from dataclasses import dataclass
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from imia.ext.sqlalchemy import SQLAlchemyORMUserProvider

metadata = sa.MetaData()
users_table = sa.Table(
    'users', metadata,
    sa.Column(sa.Integer, name='id', primary_key=True),
    sa.Column(sa.String, name='email'),
)

engine = create_async_engine('sqlite+aiosqlite:///:memory:')
async_session = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
Base = declarative_base()


class User(Base):
    __tablename__ = 'users'

    id = sa.Column(sa.Integer, primary_key=True)
    email = sa.Column(sa.String)

    ...


user_provider = SQLAlchemyORMUserProvider(async_session, User)
```

See full example in [examples/sqlalchemy_orm.py](../examples/sqlalchemy_orm.py)

Next topic is [request authentication](authentication.md).
