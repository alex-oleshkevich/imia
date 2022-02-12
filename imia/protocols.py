import typing as t
from starlette.requests import HTTPConnection


class PasswordVerifier(t.Protocol):  # pragma: no cover
    def verify(self, plain: str, hashed: str) -> bool:
        ...


class HasDisplayName(t.Protocol):  # pragma: no cover
    def get_display_name(self) -> str:
        ...


class HasId(t.Protocol):  # pragma: no cover
    def get_id(self) -> t.Any:
        ...


class HasHashedPassoword(t.Protocol):  # pragma: no cover
    def get_hashed_password(self) -> str:
        ...


class HasScopes(t.Protocol):  # pragma: no cover
    def get_scopes(self) -> t.List[str]:
        ...


class UserLike(HasId, HasScopes, HasHashedPassoword, HasDisplayName, t.Protocol):  # pragma: no cover
    ...


class Authenticator(t.Protocol):  # pragma: no cover_
    async def authenticate(self, connection: HTTPConnection) -> t.Optional[UserLike]:
        ...

    def get_auth_header(self) -> t.Optional[str]:
        ...
