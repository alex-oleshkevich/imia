# Request authentication

When an HTTP request hits is a page protected by AuthenticationMiddleware, the middleware uses authenticators to load a
user using the request data. This process is called _request authentication_. Once the authentication performed, the
request is in distinct state: you can be fully sure whether the user is authenticated or is an anonymous one. This
information stored in UserToken.

## The idea

The AuthenticationMiddleware receives one or many authenticators and iterates them on every request. The first
authenticator that returns non-None value will stop the iteration. The returned value is an instance of a user model
representing the current user. The authenticator can perform any action to get the user. It can read the database, call
external API, or return a mock user.

## Configuration

To enable authentication you need to add AuthenticationMiddleware to your application and configure the authenticator.
This is a very basic example that uses session authenticator to load users.

```python
from starlette.applications import Starlette
from starlette.middleware import Middleware

from imia import AuthenticationMiddleware, SessionAuthenticator

user_provider = ...

authenticators = [
    SessionAuthenticator(user_provider=user_provider),
]

app = Starlette(
    middleware=[
        Middleware(AuthenticationMiddleware, authenticators=authenticators),
    ]
)
```

## Multiple authenticators

You are not limited to only one authenticator instance. Moreover, you can have as many as you want. For example, the
request can be authenticated using session, API keys and Bearer tokens. To solve that challenge just setup three
instances:

```python
from imia import APIKeyAuthenticator, BearerAuthenticator, SessionAuthenticator

authenticators = [SessionAuthenticator(...), APIKeyAuthenticator(...), BearerAuthenticator(...)]
```

## Protecting only selected pages

Many applications do not need to authenticate every request. For example, landing pages are open to public while admin
area restricts access only to selected users. With Imia you can protect or exclude from protection a selected URLs using
regex patterns.

```python
from starlette.middleware import Middleware

from imia import AuthenticationMiddleware

middleware = [
    Middleware(AuthenticationMiddleware, include_patterns=['/admin', '/app'], ...)
]
```

Similarly to `include_patterns` there is `exclude_pattens` option that disables middleware for selected URLs.

```python
from starlette.middleware import Middleware

from imia import AuthenticationMiddleware

middleware = [
    Middleware(AuthenticationMiddleware, exclude_patterns=['/public', '/static'], ...)
]
```

> If both `include_patterns` and `exclude_patterns` used then the middleware will check `exclude_patterns` first.

## Failure strategies

Before we talked about cases when the request was successfully authenticated. Now it is time to see what we can do if no
authenticator can load the user.

Out of the box Imia provides three actions: raise `AuthenticationError`, redirect to another URL and ignore.

### Raising AuthenticationError

This strategy will raise `imia.AuthenticationError` if all authenticators fail. Use a global error handler to catch the
exception and properly handle it.

```python
from starlette.middleware import Middleware

from imia import AuthenticationMiddleware

middleware = [
    Middleware(AuthenticationMiddleware, on_failure='raise', ...)
]
```

### Redirecting to a login page

Some application may need to redirect users to another URL, usually a login page. To enable redirection set `on_failure`
to `redirect` and add extra `redirect_to` argument. The `redirect_to` arguments is a destination URL.

```python
from starlette.middleware import Middleware

from imia import AuthenticationMiddleware

middleware = [
    Middleware(AuthenticationMiddleware, on_failure='redirect', redirect_to='/login', ...)
]
```

### Ignore authentication errors

When you go this scenario no action will be performed and your controller/view will receive an unauthenticated request.
Do not forget to check `request.auth.is_authenticated` to make sure you are still protecting sensitive data.

## Retrieving the authenticated user

You can get currently authenticated user from [user token](user_token.md):

```python
from starlette.responses import PlainTextResponse


def app_view(request):
    user = request.auth.user
    return PlainTextResponse(f'hello {user}!')
```

> If the request is unauthenticated the user will be an instance of `AnonymousUser` class.

## Checking if user is authenticated

To quickly check if current user is not anonymous, use `request.auth` in `if` statement.

```python
from starlette.responses import PlainTextResponse


def app_view(request):
    if request.auth:
        return PlainTextResponse('you are authenticated')
    return PlainTextResponse('you are not authenticated')
```

If you want more details about authentication state, inpect the [user token](user_token.md).


## Authenticating manually

Instead of using middleware, you can use `imia.authentication.authenticate` function to manually authenticate the request.
In this case, you can run it anywhere in the code and remove `AuthenticationMiddleware` from the middleware list.

```python
from imia.authentication import authenticate, SessionAuthenticator, BearerAuthenticator
from starlette.responses import PlainTextResponse

authenticators = [
    SessionAuthenticator(...),
    BearerAuthenticator(...),
]

async def index_view(request):
    user_token = await authenticate(request, authenticators)
    if user_token:
        return PlainTextResponse('you are authenticated')
    else:
        return PlainTextResponse('you are not authenticated')
```

> Note, that `request.auth` won't be filled in this case and may raise exception.

## Next topic

The next topic of this guide will describe [built-in authenticators](authenticators.md).
