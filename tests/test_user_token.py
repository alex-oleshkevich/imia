import dataclasses

import typing as t

from imia import AnonymousUser, LoginState, UserToken


@dataclasses.dataclass
class User:
    identifier: str = 'root@localhost'
    password: str = 'pa$$word'
    scopes: t.List[str] = dataclasses.field(default_factory=list)
    name: str = 'Root'

    def get_display_name(self):
        return 'Root'

    def get_id(self):
        return self.identifier

    def get_hashed_password(self):
        return self.password

    def get_scopes(self):
        return self.scopes


def test_user_token():
    user = User(scopes=['a'])
    token = UserToken(user, state=LoginState.FRESH)
    assert token.is_authenticated
    assert not token.is_anonymous
    assert token.original_user_token is None
    assert token.original_user_id is None
    assert token.scopes == ['a']
    assert token.user_id == 'root@localhost'
    assert token.user == user
    assert token.display_name == 'Root'
    assert token.state == LoginState.FRESH
    assert bool(token)
    assert str(token) == 'Root'
    assert 'a' in token


def test_anon_user_token():
    user = AnonymousUser()
    token = UserToken(user, state=LoginState.ANONYMOUS)
    assert not token.is_authenticated
    assert token.is_anonymous
    assert token.original_user_token is None
    assert token.original_user_id is None
    assert token.scopes == []
    assert token.user_id is None
    assert token.user == user
    assert token.display_name == 'Anonymous'
    assert token.state == LoginState.ANONYMOUS
    assert not bool(token)
    assert str(token) == 'Anonymous'


def test_impersonated_user_token():
    user = User()
    root_token = UserToken(user, state=LoginState.FRESH)

    customer = User(identifier='customer@localhost', name='Customer')
    token = UserToken(customer, state=LoginState.IMPERSONATOR, original_user_token=root_token)

    assert token.user_id == 'customer@localhost'
    assert token.original_user_token == root_token
    assert token.original_user_id == 'root@localhost'
