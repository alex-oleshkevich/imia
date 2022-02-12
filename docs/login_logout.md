# Login / logout

Session-based logins and logouts are covered by this library out of the box.

## How it works

The main component in login/logout flow is `imia.LoginManager` class. This class uses user provider to load user from
the storage by email/username and [a password verifier](password_verification.md) to compare passwords. Once your user
is authenticated it will be stored in the session. Thus, you have to enable
either [`starsessions.SessionMiddleware`](https://github.com/alex-oleshkevich/starsessions) (recommended) or
[`starlette.middleware.sessions.SessionMiddleware`](https://www.starlette.io/middleware/#sessionmiddleware) to make it
work.

## Login manager

> **Warning:** LoginManager API may change in the future.

Login manager is a central facade to login/logout users.

> Login manager always returns an instance of UserToken. You have to always check if it is True:

```python
user_token = await login_manager.login()
if user_token:
    print('authenticated')
```

```python
# views.py
if await login_manager.login():
    print('authenticated)
```

## Logging in users

Use `login(request, identity, credential)` method of `LoginManager` to log in users. An identity may be a username, or
email, or other criteria. A credential can be a password, or a one-time token, or another solution.

```python
from starlette.requests import Request
from starlette.responses import RedirectResponse

from imia import LoginManager

secret_key = 'key!'
user_provider = ...
password_verifier = ...

login_manager = LoginManager(user_provider, password_verifier, secret_key)


async def login_view(request: Request):
    if request.method == 'POST':
        data = await request.form()
        email = data['email']
        password = data['password']

        user_token = await login_manager.login(request, email, password)
        if user_token:
            return RedirectResponse('/app', status_code=302)
        else:
            return RedirectResponse('/login?error=invalid_credentials', status_code=302)
```

## Login guards

Login guards can protect login page usign complex custom logic defined by the developer. For example, you may use them
to prevent bruteforce attacks, prevents inactive users from log in, and can perform other security related actions.

The login guard is an async callable that should raise any exception to abort login flow.

```python
from imia import LoginManager

login_manager = LoginManager(...)


class TooManyAttempts(Exception): ...


class InactiveUser(Exception): ...


def throttle_logins(request, user):
    if user.login_attemts > 3:
        raise TooManyAttempts()


def require_active_user(request, user):
    if not user.is_active:
        raise InactiveUser()


async def logout_view(request):
    if request.method == 'POST':
        data = await request.form()
        email = data['email']
        password = data['password']

        try:
            user_token = await login_manager.login(
                request, email, password, guards=[throttle_logins, require_active_user()]
            )
            if user_token:
                return RedirectResponse('/app', status_code=302)
            else:
                return RedirectResponse('/login?error=invalid_credentials', status_code=302)
        except TooManyAttempts:
            return RedirectResponse('/login?error=too_many_attempts', status_code=302)
        except InactiveUser:
            return RedirectResponse('/login?error=inactive_user', status_code=302)
```

## Logout usage

With `logout(request) -> None` method of LoginManager you can terminate user's session.

```python
from imia import LoginManager

login_manager = LoginManager(...)


async def logout_view(request):
    await login_manager.logout(request)
    return RedirectResponse('/login')
```

Note, the user session, and it's data will be destroyed.

## Session security

In some cases library regenerates session ID to improve security. If your session instance (the one obtained
from `request.session`)
implements `async def regenerate_id(self) -> typing.Any` it will be called. It is strongly advised to have it. Or use
this library [`starsessions.SessionMiddleware`](https://github.com/alex-oleshkevich/starsessions)
that natively integrates with Imia.

## Logging in users manually

When LoginManager cannot satisfy your requirements you can use a low-level `login_user(request, user, secret_key)`
function. The user loading and password verification is up to you.

```python
from imia import login_user

secret_key = 'key!'


async def custom_login_view(request):
    user = ...
    secret_key = ...
    await login_user(request, user, secret_key)
    return RedirectResponse('/app')
```

This function may be useful in unit tests to force login of a specific user.

## Next topic

Read how temporary [impersonate other users](impersonation.md).
