# Login / logout

## How it works

The main component in login/logout flow is `imia.LoginManager` class. This class uses user provider to load user from
the storage by email/username and a password verifier to compare passwords. Once your user is authenticated it will be
stored in the session. Thus, you have to enable
either [`starsessions.SessionMiddleware`](https://github.com/alex-oleshkevich/starsessions) (recommended) or
[`starlette.middleware.sessions.SessionMiddleware`](https://www.starlette.io/middleware/#sessionmiddleware) to make it
work.

## Login usage

Here is an example function to log in users

```python
from starlette.requests import Request
from starlette.responses import RedirectResponse

from imia import LoginManager

secret_key = 'key!'
user_provider = MyUserProvider()  # see Configuration page
password_verifier = MyPasswordVerifier()  # see Configuration page

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

## Logout usage

In order to log out uses use `LoginManager.logout` method:

```python
async def logout_view(request: Request):
    await login_manager.logout(request)
    return RedirectResponse('/login')
```

Note, the user session and it's data will be destroyed.

## Session security

In some cases library regenerates session ID to improve security. If your session instance (the one obtained
from `request.session`)
implements `async def regenerate_id(self) -> Any` it will be called. It is strongly advised to have it. Or use this
library [`starsessions.SessionMiddleware`](https://github.com/alex-oleshkevich/starsessions)
that natively integrates with Imia.

## Custom login or log in users manually

Use `login_user` function to customize the login flow. If you go this direction, it is up to you to load user, compare
passwords. Once you got an user instance then call `login_user` to login.

```python
from imia import login_user

secret_key = 'key!'


async def custom_login_view(request):
    user = my_own_authentication_fn(request)
    await login_user(request, user, secret_key)
    return RedirectResponse('/app')
```

