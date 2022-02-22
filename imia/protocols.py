import typing
from starlette.requests import HTTPConnection, Request


class PasswordVerifier(typing.Protocol):  # pragma: no cover
    def verify(self, plain: str, hashed: str) -> bool:
        ...


class HasDisplayName(typing.Protocol):  # pragma: no cover
    def get_display_name(self) -> str:
        ...


class HasId(typing.Protocol):  # pragma: no cover
    def get_id(self) -> typing.Any:
        ...


class HasHashedPassoword(typing.Protocol):  # pragma: no cover
    def get_hashed_password(self) -> str:
        ...


class HasScopes(typing.Protocol):  # pragma: no cover
    def get_scopes(self) -> typing.List[str]:
        ...


class UserLike(HasId, HasScopes, HasHashedPassoword, HasDisplayName, typing.Protocol):  # pragma: no cover
    ...


class LoginGuard(typing.Protocol):
    async def __call__(self, request: Request, user: UserLike) -> None:
        ...


class Authenticator(typing.Protocol):  # pragma: no cover_
    async def authenticate(self, connection: HTTPConnection) -> typing.Optional[UserLike]:
        ...

    def get_auth_header(self) -> typing.Optional[str]:
        ...
