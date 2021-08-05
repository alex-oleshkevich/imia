import typing as t
from starlette.requests import HTTPConnection


class PasswordVerifier(t.Protocol):  # pragma: no cover
    def verify(self, plain: str, hashed: str) -> bool:
        ...


class UserLike(t.Protocol):  # pragma: no cover_
    def get_display_name(self) -> str:
        ...

    def get_id(self) -> t.Any:
        ...

    def get_hashed_password(self) -> str:
        ...

    def get_scopes(self) -> t.List[str]:
        ...


class Authenticator(t.Protocol):  # pragma: no cover_
    async def authenticate(self, connection: HTTPConnection) -> t.Optional[UserLike]:
        ...

    def get_auth_header(self) -> t.Optional[str]:
        ...
