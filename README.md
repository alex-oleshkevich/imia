# Imia

Imia (belarussian for "a name") is an authentication library for Starlette and FastAPI (python 3.8+).

![PyPI](https://img.shields.io/pypi/v/imia)
![GitHub Workflow Status](https://img.shields.io/github/workflow/status/alex-oleshkevich/imia/Lint)
![GitHub](https://img.shields.io/github/license/alex-oleshkevich/imia)
![Libraries.io dependency status for latest release](https://img.shields.io/librariesio/release/pypi/imia)
![PyPI - Downloads](https://img.shields.io/pypi/dm/imia)
![GitHub Release Date](https://img.shields.io/github/release-date/alex-oleshkevich/imia)
![Lines of code](https://img.shields.io/tokei/lines/github/alex-oleshkevich/imia)

## Production status

The library is considered in "beta" state thus may contain bugs or security issues, but I actively use it in production.

## Installation

Install `imia` using PIP or poetry:

```bash
pip install imia
# or
poetry add imia
```

## Features

- Login/logout flows
- Pluggable authenticators:
    - WWW-Basic
    - session
    - token
    - bearer token
    - any token (customizable)
    - API key
- Database agnostic user storage
- Authentication middleware
    - with fallback strategies:
        - redirect to an URL
        - raise an exception
        - do nothing
    - with optional URL protection
    - with option URL exclusion from protection
- User Impersonation (stateless and stateful)
- SQLAlchemy 1.4 (async mode) integration

## TODO

* remember me

## A very quick start

If you are too lazy to read this doc, take a look into `examples/` directory. There you will find several files demoing
various parts of this library.

## How it works?

Here are all moving parts:

1. **UserLike** object, aka "user model" - is an arbitrary class that implements `imia.UserLike` protocol.
2. **a user provider** - an adapter that loads user model (UserLike object) from the storage (a database).
3. **an authenticator** - a class that loads user using the user provider from the request (eg. session)
4. **an authentication middleware** that accepts an HTTP request and calls authenticators for a user model. The
   middleware always populates `request.auth` with `UserToken`.
6. **user token** is a class that holds authentication state

When a HTTP request reaches your application, an `imia.AuthenticationMiddleware` will start handling it. The middleware
iterates over configured authenticators and stops on the first one that returns non-None value. At this point the
request is considered authenticated. If no authenticators return user model then the middleware will create  _anonymous
user token_. The user token available in `request.auth` property. Use `user_token.is_authenticated` token property to
make sure that user is authenticated.

## User authentication quick start

1. Create a user model and implement methods defined by `imia.UserLike` protocol.
2. Create an instance of `imia.UserProvider` that corresponds to your user storage. Feel free to create your own.
3. Setup one or more authenticators and pass them to the middleware
4. Add `imia.AuthenticationMiddleware` to your Starlette application

At this point you are done.

Here is a brief example that uses in-memory provider for demo purpose. For production environment you should use
database backed providers like `SQLAlchemyORMUserProvider` or  `SQLAlchemyCoreUserProvider`. Also, for simplicity reason
we will not implement [login/logout flow](docs/login_logout.md) and will authenticate requests using API keys.

```python
from dataclasses import dataclass, field

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from imia import APIKeyAuthenticator, AuthenticationMiddleware, InMemoryProvider


@dataclass
class User:
    """This is our user model. It may be an ORM model, or any python class, the library does not care of it,
    it only expects that the class has methods defined by the UserLike protocol."""

    id: str
    password: str = 'password'
    scopes: list[str] = field(default_factory=list)

    def get_display_name(self) -> str:
        return self.id.split('@')[0].title()

    def get_id(self) -> str:
        return self.id

    def get_hashed_password(self) -> str:
        return self.password

    def get_scopes(self) -> list:
        return self.scopes


async def whoami_view(request: Request) -> JSONResponse:
    return JSONResponse({
        'id': request.auth.user_id,
        'name': request.auth.display_name,
    })


user_provider = InMemoryProvider({
    'user1@example.com': User(id='user1@example.com'),
    'user2@example.com': User(id='user2@example.com'),
})

authenticators = [
    APIKeyAuthenticator(user_provider=user_provider),
]

routes = [
    Route('/', whoami_view),
]

middleware = [
    Middleware(AuthenticationMiddleware, authenticators=authenticators)
]

app = Starlette(routes=routes, middleware=middleware)
```

Now save the file to `myapp.py` and run it with [uvicorn](https://uvicorn.org) application server:

```bash
uvicorn myapp:app
```

Open `http://127.0.0.1:8000/` and see that your request is not authenticated and user is anonymous. Let's pass API key
via query parameters to make the configured APIKeyAuthenticator to load user. This time
open `http://127.0.0.1:8000/?apikey=user1@example.com` in your browser. Now the request is fully authenticated as User1
user.

For more details refer to the doc sections below.

## Docs

1. [UserLike protocol (a user model)](docs/userlike_protocol.md)
2. [Load user from databases using User Providers](docs/user_providers.md)
6. [Request authentication](docs/authentication.md)
7. [Built-in authenticators](docs/authenticators.md)
5. [User token](docs/user_token.md)
5. [Passwords](docs/password_verification.md)
4. [Login/Logout flow](docs/login_logout.md)
8. [User impersontation](docs/impersonation.md)

## Usage

See [examples/](examples) directory.
