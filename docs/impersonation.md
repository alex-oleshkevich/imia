# Impersonation

An impersonation is when someone pretends to be another person. In other words, you can temporarily become another user
and see your application as they see it.

## Configuration

Add `imia.ImpersonationMiddleware` to your middleware list. This middleware accepts these options:

| Option | Default | Type | Description |
|--------|---------|------|-------------|
| user_provider | required | UserProvider | A user provider instance. | 
| guard_fn | None | typing.Callable[[UserToken, HTTPConnection], bool] | A callable to check if the current user can switch users. | 
| enter_query_param | '_impersonate' | str | A query param name that triggers impersonation. | 
| exit_user_name | '__exit__' | str | A magic value of "enter_query_param" to disable impersonation. | 
| scope | 'auth:impersonate_others' | str | A permission that allows switching users. | 

### Usage

```python
from starlette.middleware import Middleware

from imia import ImpersonationMiddleware

user_provider = ...

middleware = [
    Middleware(ImpersonationMiddleware, user_provider=user_provider)
]
```

## Security

As impersonation can expose a sensitive data to other users, there are two security options available.

### Using user scopes to restrict impersonation

By default, a user has to have a permission named `auth:impersonate_others` in the scope. When a user without the
permission will try to activate impersonation nothing will happen.

### Using guard function for fine-grained control

Alternatively, you can provide a callable via `guard_fn(user_token, request)` argument of the middleware. The guard
accepts two arguments: `imia.UserToken` and `starlette.requests.HTTPConnection` and must return a boolean value.

> The guard function takes precedence over scope and always used when available.

```python
from imia import ImpersonationMiddleware
from starlette.middleware import Middleware


def guard(user_token, request):
    return user_token.user_id == 42


middleware = [
    Middleware(ImpersonationMiddleware, guard_fn=guard)
]
```

## Impersonation types

An impersonation session may be stateless and stateful. With stateless kind you have to always pass `_impersonate` in
your URL while stateful remembers state in the session and will remain is active until you deactivate it, or till
session expiration. The stateful depends on session.

> A stateful type will be used automatically if session middleware is added.

## Activate impersonation session

Access you page with a special request param to activate the impersonation session. For example:

```shell
curl https://example.com/app?_impersonate=customer@localhost
```

Your application will see this request as if "customer@localhost" accessed it. If you have sessions enabled then you
don't need to pass this key to any further requests, the state is remembered in the session.

> You can configure `_impersonate` key name with `enter_query_param` middleware option.

## Deactivate impersonation session

To deactivate settings, add `_impersonate=__exit__` to your URL.

```shell
curl https://example.com/app?_impersonate=__exit__
```

You will get back to your original user.

> You can change `__exit__` to another value using `exit_user_name` middleware option.

## When to use?

For example, site admin may need to log in as customers to see what they see to assist them. Instead of asking them for
credentials, admins can temporary become them. This is like "su" command in Unix systems.
