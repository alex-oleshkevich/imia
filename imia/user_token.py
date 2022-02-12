from __future__ import annotations

import enum
import typing as t

from .protocols import UserLike


class LoginState(enum.Enum):
    ANONYMOUS = "ANONYMOUS"
    IMPERSONATOR = "IMPERSONATOR"
    REMEMBERED = "REMEMBERED"
    FRESH = "FRESH"


class UserToken:
    __slots__ = ["_user", "_state", 'original_user_token']

    def __init__(
        self,
        user: UserLike,
        state: LoginState,
        original_user_token: UserToken = None,
    ) -> None:
        self._user = user
        self._state = state
        self.original_user_token = original_user_token

    @property
    def is_authenticated(self) -> bool:
        """
        Get authentication state.

        Returns True is user is authenticated.
        """
        return self.state != LoginState.ANONYMOUS

    @property
    def is_anonymous(self) -> bool:
        """Test if current user is not authenticated (anonymous)."""
        return not self.is_authenticated

    @property
    def original_user_id(self) -> t.Optional[t.Any]:
        """Get ID of user being impersonated."""
        return self.original_user_token.user.get_id() if self.original_user_token else None

    @property
    def scopes(self) -> t.List[str]:
        """
        Return permission scopes of current user.

        Returns an empty list for unauthenticated user.
        """
        return self.user.get_scopes()

    @property
    def user_id(self) -> t.Any:
        """Get ID of current user."""
        return self.user.get_id()

    @property
    def user(self) -> UserLike:
        """Get an user model associated."""
        return self._user

    @property
    def display_name(self) -> str:
        """Get a display name of current user."""
        return self.user.get_display_name()

    @property
    def state(self) -> LoginState:
        """Get a login state."""
        return self._state

    def __bool__(self) -> bool:
        """Support if-like usage:
        if user_token:
            ...
        """
        return self.is_authenticated

    def __str__(self) -> str:
        return self.display_name

    def __contains__(self, permission: str) -> bool:
        """Check if permission is in scopes."""
        return permission in self.scopes


class AnonymousUser:
    def get_display_name(self) -> str:
        return 'Anonymous'

    def get_id(self) -> t.Any:
        return None

    def get_hashed_password(self) -> str:
        return ''

    def get_scopes(self) -> t.List[str]:
        return []
