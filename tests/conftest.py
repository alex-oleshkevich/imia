import dataclasses
from dataclasses import dataclass

import pytest
import typing as t
from starlette.requests import HTTPConnection

from imia import InMemoryProvider


@pytest.fixture
def http_scope() -> dict:
    return {
        'type': 'http',
    }


@pytest.fixture()
def http_connection(http_scope: dict) -> HTTPConnection:
    return HTTPConnection(http_scope)


@dataclass
class User:  # pragma: no cover_
    identifier = 'root@localhost'
    password = 'pa$$word'
    scopes: t.List[str] = dataclasses.field(default_factory=list)
    name = 'Root'

    def get_display_name(self) -> str:
        return 'Root'

    def get_id(self) -> t.Any:
        return self.identifier

    def get_hashed_password(self) -> str:
        return self.password

    def get_scopes(self) -> t.List[str]:
        return self.scopes


@dataclass
class CustomerUser(User):
    identifier = 'customer@localhost'
    name = 'Customer'


class UnsafePasswordVerifier:
    def verify(self, plain: str, hashed: str) -> bool:
        return plain == hashed


user = User()
customer_user = CustomerUser()

inmemory_user_provider = InMemoryProvider(
    {
        'root@localhost': user,
        'customer@localhost': customer_user,
    }
)
password_verifier = UnsafePasswordVerifier()
