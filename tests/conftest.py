import dataclasses
from dataclasses import dataclass

from imia import InMemoryProvider


@dataclass
class User:
    identifier = 'root@localhost'
    password = 'pa$$word'
    scopes: list[str] = dataclasses.field(default=list)

    def get_display_name(self):
        return 'Root'

    def get_identifier(self):
        return self.identifier

    def get_hashed_password(self):
        return self.password

    def get_scopes(self):
        return self.scopes


class UnsafePasswordVerifier:
    def verify(self, plain: str, hashed: str) -> bool:
        return plain == hashed


inmemory_user_provider = InMemoryProvider(
    {
        'root@localhost': User(),
    }
)
password_verifier = UnsafePasswordVerifier()
