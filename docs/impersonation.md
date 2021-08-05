# Impersonation

Impersonation is when someone pretends to be another person. In other words, you can temporarily become another user and
see your application as they see it.

## Configuration

Add `imia.ImpersonationMiddleware` to your middleware list. This middleware accepts there options:

* `user_provider` a user provider
* `guard_fn` (optional) a function to check if current user can switch users
* `enter_query_param`  (optional, default "_impersonate") a request query param name that triggers impersonation
* `exit_user_name`  (optional, default "___exit__") a magic value of "enter_query_param" to disable impersonation
* `scope` (optional, default "auth:impersonate_others") a user's permission that allows switching users

## Security

As impersonation can expose a sensitive data to other users, there are two security options available.

### Using user scopes to restrict impersonation

By default, a user has to have a permission named `auth:impersonate_others` in the scope. When such user tries to
activate impersonation nothing will happen.

### Using guard function for fine-grained control

Alternatively, you can provide a callable via `guard_fn` argument of the middleware. The guard accepts two
arguments: `imia.UserToken` and `starlette.requests.HTTPConnection` and must return a boolean value.

The guard function takes precedence over scope and always used when available.

Example:

```python
def guard(token: UserToken, request: HTTPConnection):
    return token.user_id == 42
```

## Usage

```python
import dataclasses
import typing as t

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware

from imia import APIKeyAuthenticator, AuthenticationMiddleware,
from user_providers import InMemoryProvider
from impersonation import ImpersonationMiddleware


@dataclasses.dataclass()
class User:
    id: str
    name: str
    scopes: list[str] = None

    def get_id(self) -> t.Any:
        return self.id

    def get_display_name(self) -> str:
        return self.name

    def get_hashed_password(self) -> str:
        return 'password'

    def get_scopes(self) -> t.List[str]:
        return self.scopes or []
        return ['auth:impersonate_others']


user_provider = InMemoryProvider({
    'root@localhost': User(id='root@localhost', name='root', scopes=['auth:impersonate_others']),
    'customer@localhost': User(id='customer@localhost', name='customer', scopes=[]),
})

app = Starlette(
    middleware=[
        Middleware(SessionMiddleware, secret_key='key!'),
        Middleware(
            AuthenticationMiddleware,
            authenticators=[APIKeyAuthenticator(user_provider=user_provider)],
        ),
        Middleware(
            ImpersonationMiddleware,
            user_provider=user_provider,
        )
    ]
)
```

## Impersonation types

An impersonation session may be stateless and stateful. With stateless kind you have to always pass `_impersonate` in
your URL while stateful remembers settings in the session and is active until you deactivate it. The stateful depends on
session.

## Activate impersonation session

Access you page with a special request param to activate the impersonation session. For example:

```shell
curl https://example.com/app?_impersonate=customer@localhost
```

Your application will see this request as if "customer@localhost" accessed it. If you have sessions enabled then you
don't need to pass this key to any further requests, the state is remembered in the session.

Note, you can configure `_impersonate` key name with `enter_query_param` middleware option.

## Deactivate impersonation session

To deactivate settings, add `_impersonate=__exit__` to your URL.

```shell
curl https://example.com/app?_impersonate=__exit__
```

You will get back to your user.

Note, you can change `__exit__` to another value using `exit_user_name` middleware option.  
