import dataclasses
from dataclasses import dataclass

import typing as t

from imia import InMemoryProvider


@dataclass
class User:
    identifier = 'root@localhost'
    password = 'pa$$word'
    scopes: t.List[str] = dataclasses.field(default_factory=list)
    name = 'Root'

    def get_display_name(self):
        return 'Root'

    def get_id(self):
        return self.identifier

    def get_hashed_password(self):
        return self.password

    def get_scopes(self):
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
