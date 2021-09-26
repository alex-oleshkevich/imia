from imia import AnonymousUser


def test_anon_user() -> None:
    user = AnonymousUser()
    assert user.get_id() is None
    assert user.get_scopes() == []
    assert user.get_hashed_password() == ''
    assert user.get_display_name() == 'Anonymous'
