# Password verification

The library does not provide own solution to check user passwords but accepts any class that
implements `PasswordVerifier` protocol in places where it needs to check the password.

You also can use [passlib](https://passlib.readthedocs.io/en/stable/) as is with this library.

The password gets verified in [login/logout flow](login_logout.md) and by [HTTP Basic Authenticator](authenticators.md).

## Using passlib

> Install passlib before using it

```python
from passlib.hash import pbkdf2_sha1

from imia import LoginManager

login_manager = LoginManager(password_verifier=pbkdf2_sha1, ...)
```

## Writing custom verifiers

A custom verifier is a class that has `verify(plan, hashed) -> bool` method.

```python
from imia import LoginManager


class MyPasswordVerifier:
    def verify(self, plain: str, hashed: str) -> bool:
        return hashed == plain


login_manager = LoginManager(password_verifier=MyPasswordVerifier(), ...)
```

## Next topic

Proceed to [login/logout flow](login_logout.md)
