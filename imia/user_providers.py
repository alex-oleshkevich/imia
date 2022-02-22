import abc
import typing
from starlette.requests import HTTPConnection

from .protocols import UserLike


class UserProvider(abc.ABC):  # pragma: no cover
    """
    User provides perform user look ups over data storages.

    These classes are consumed by Authenticator instances and are not designed
    to be a part of login or logout process.
    """

    async def find_by_id(self, connection: HTTPConnection, identifier: typing.Any) -> typing.Optional[UserLike]:
        """Look up a user by ID."""
        raise NotImplementedError()

    async def find_by_username(self, connection: HTTPConnection, username_or_email: str) -> typing.Optional[UserLike]:
        """
        Look up a user by it's identity.

        Where identity may be an email address, or username.
        """
        raise NotImplementedError()

    async def find_by_token(self, connection: HTTPConnection, token: str) -> typing.Optional[UserLike]:
        """Look up a user using API token."""
        raise NotImplementedError()


class InMemoryProvider(UserProvider):
    """A user provides that uses a predefined map of users."""

    def __init__(self, user_map: typing.Mapping[typing.Any, UserLike]) -> None:
        self.user_map = user_map

    async def find_by_id(self, connection: HTTPConnection, identifier: str) -> typing.Optional[UserLike]:
        return self.user_map.get(identifier)

    async def find_by_username(self, connection: HTTPConnection, username_or_email: str) -> typing.Optional[UserLike]:
        return self.user_map.get(username_or_email)

    async def find_by_token(self, connection: HTTPConnection, token: str) -> typing.Optional[UserLike]:
        return self.user_map.get(token)
