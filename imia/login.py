import hashlib
import hmac
import secrets
import typing as t
from starlette.requests import HTTPConnection

from .exceptions import SessionReusageError
from .protocols import PasswordVerifier, UserLike
from .user_providers import UserProvider
from .user_token import AnonymousUser, LoginState, UserToken

SESSION_KEY = '_auth_user_id'
SESSION_HASH = '_auth_user_hash'
HASHING_ALGORITHM = 'sha1'


def get_session_auth_id(connection: HTTPConnection) -> t.Optional[str]:
    return connection.session.get(SESSION_KEY)


def get_session_auth_hash(connection: HTTPConnection) -> t.Optional[str]:
    return connection.session.get(SESSION_HASH)


async def update_session_auth_hash(request: HTTPConnection, user: UserLike, secret_key: str) -> None:
    """Update current session's SESSION_HASH key.
    Call this function in your password reset form otherwise you will be logged out."""
    if hasattr(request.session, 'regenerate_id'):
        await request.session.regenerate_id()  # type: ignore
    request.session[SESSION_HASH] = _get_password_hmac_from_user(user, secret_key)


def _get_password_hmac_from_user(user: UserLike, secret: str) -> str:
    """Generate HMAC value for user's password."""
    key = hashlib.sha256(("imia.session.hash" + secret).encode()).digest()
    return hmac.new(key, msg=user.get_hashed_password().encode(), digestmod=hashlib.sha1).hexdigest()


def _check_for_other_user_session(connection: HTTPConnection, user: UserLike, user_password_hmac: str) -> None:
    """There is a chance that session may already contain data of another user.
    This may happen if you don't clear session property on logout, or SESSION_KEY is set from the outside.
    In this case we need to run several security checks to ensure that SESSION_KEY is valid.

    Our plan:
        * if SESSION_KEY and ID of current user is not the same -> risk of session re-usage
        * if session hash is not the same as hash for user's password then we clearly reusing other's session.
    """
    session_auth_hmac = get_session_auth_hash(connection)
    if SESSION_KEY in connection.session and any(
        [
            # if we have other user id in the session
            connection.session[SESSION_KEY] != str(user.get_id()),
            # and session has previously set hash, and hashes are not equal
            session_auth_hmac and not secrets.compare_digest(session_auth_hmac, user_password_hmac),
        ]
    ):
        # probably this is the session of another user -> clear
        raise SessionReusageError()


async def login_user(request: HTTPConnection, user: UserLike, secret_key: str) -> UserToken:
    """Login a user w/o password check."""
    user_password_hmac = _get_password_hmac_from_user(user, secret_key)
    try:
        _check_for_other_user_session(request, user, user_password_hmac)
    except SessionReusageError:
        request.session.clear()
    else:
        if hasattr(request.session, 'regenerate_id'):
            # if session implements `def regenerate_id(self) -> str` then call it
            await request.session.regenerate_id()  # type: ignore

    user_token = UserToken(user=user, state=LoginState.FRESH)
    request.session[SESSION_KEY] = str(user.get_id())
    request.session[SESSION_HASH] = user_password_hmac
    request.scope['auth'] = user_token
    return user_token


class LoginManager:
    """Use this class to handle login and logout forms."""

    def __init__(self, user_provider: UserProvider, password_verifier: PasswordVerifier, secret_key: str = '') -> None:
        self._user_provider = user_provider
        self._password_verifier = password_verifier
        self._secret_key = secret_key

    async def login(self, request: HTTPConnection, username: str, password: str) -> UserToken:
        user = await self._user_provider.find_by_username(username)
        if user is not None and self._password_verifier.verify(password, user.get_hashed_password()):
            return await login_user(request, user, self._secret_key)
        return UserToken(user=AnonymousUser(), state=LoginState.ANONYMOUS)

    async def logout(self, request: HTTPConnection) -> None:
        request.session.clear()
        if hasattr(request.session, 'regenerate_id'):
            await request.session.regenerate_id()  # type: ignore

        request.scope['auth'] = UserToken(user=AnonymousUser(), state=LoginState.ANONYMOUS)
