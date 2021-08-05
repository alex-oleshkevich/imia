# Configure the application

This library requires you to set up these components before you proceed:

* a user model that matches `imia.UserLike` [protocol](https://www.python.org/dev/peps/pep-0544/).
* create class that implements a `imia.PasswordVerifier` protocol to compare passwords
* create a `imia.UserProvider` class to load users from your storage
* a `secret_key` to improve security

## User model

We don't know details about your other model. Instead, we define a protocol called `imia.UserLike` that we expect your
model to implement. The protocol defines `imia.UserLike` following methods:

* `def get_display_name(self) -> str` returns a string representation of user. Usually a full name.
* `def get_id(self) -> Any` returns ID of user.
* `def get_hashed_password(self) -> str` returns a hashed password string
* `def get_scopes(self) -> list[str]` returns list of permission scopes

A example dataclass-based user may look like this:

```python
import dataclasses
import typing as t


@dataclasses.dataclass()
class User:
    id: str
    name: str
    email: str
    password: str
    scopes: list[str]
    api_token: str = None

    def get_display_name(self) -> str:
        return self.name

    def get_id(self) -> t.Any:
        return self.id

    def get_hashed_password(self) -> str:
        return self.password

    def get_scopes(self) -> list[str]:
        return self.scopes
```

## User provider

User provider is a storage-talking utility. We use it to contact your database backend to load users. So, your
application needs to give one to us. We expose a `imia.UserProvider` base class for use in your derived classes.

Let's create a memory-based user provider that stores users in the process memory.

```python
import typing as t

from imia import UserProvider, UserLike

_users: list[User] = []


class MyUserProvider(UserProvider):
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

Our library exports `imia.InMemoryProvider` that you can use in unit tests.

## Password verifier

Upon login, we compare hashed password provided by your model with a plain password from the request. This is
what `imia.PasswordVerifier` is about. You can use [passlib](https://passlib.readthedocs.io/en/stable/)
for this purpose, this library's `PasswordVerifier` is modelled from it.

```python
class MyPasswordVerifier:
    def verify(self, plain: str, hashed: str) -> bool:
        return hashed == plain
```

As mentioned, you can use `passlib` in places where you need a password verifier. For example, when constructing login
manager:

```python
from passlib.hash import pbkdf2_sha1

from imia import LoginManager

login_manager = LoginManager(user_provider=None, password_verifier=pbkdf2_sha1)
```

They have compatible interfaces.
