# Request authentication

When a request hits our application, we use request to identify the user. This process is called *request
authentication*. Out of the box, we support several common strategies.

The request authentication is backed by `imia.AuthenticationMiddleware`.

## Configuration

Here is an example setup:

```python
from starlette.middleware import Middleware
from starlette.applications import Starlette
from imia import AuthenticationMiddleware

app = Starlette(
    middleware=[
        Middleware(
            AuthenticationMiddleware,
            authenticators=[], on_failure="raise", redirect_to="/", 
            exclude_patterns=[], include_patterns=[],
        )
    ]
)
```

`AuthenticationMiddleware` accepts following arguments:

* `authenticators` a list of authenticators. The middleware will call each to get a user instance from the request
* `on_failure` a fallback action to execute when user cannot be loaded from the request. Possible choices are:
    * "raise" will raise `imia.AuthenticationError` exception
    * "redirect" will redirect user to a "redirect_to" URL (see below)
    * "do_nothing" continue as anonymous user
* `redirect_to` a URL to redirect user to when the middleware fails to load user instance. A regex is allowed as a
  pattern. Note, that the full URL is checked: `https://example.com/app`, not just path `/app`.
* `exclude_patterns` the middleware **WILL NOT** authenticate requests that match at least one pattern from the list
* `include_patterns` **ONLY MATCHING** requests will be authenticated, others ignored

## Authenticator usage

The middleware accepts one or many authenticator instances. It will iterate over all authenticator asking them to find a
user instance. If no authenticators can provide a user, the middleware will execute a fallback strategy. Or, will break on
the first authenticator that returns a user instance.

```python
from starlette.middleware import Middleware
from starlette.applications import Starlette
from imia import AuthenticationMiddleware, APIKeyAuthenticator, TokenAuthenticator, HTTPBasicAuthenticator

user_provider = MyUserProvider()
password_verifier = MyPasswordVerifier()

app = Starlette(
    middleware=[
        Middleware(
            AuthenticationMiddleware,
            authenticators=[
                HTTPBasicAuthenticator(user_provider, password_verifier)
                APIKeyAuthenticator(user_provider),
                TokenAuthenticator(user_provider, 'Bearer'),
            ]
        )
    ]
)
```

## Use cases

### Protecting specific parts of the application

Very often, you want to require authentication for specific areas only, like `/app` or `/admin`. You can achieve it with
this configuration:

```python
Middleware(
    AuthenticationMiddleware,
    authenticators=[], on_failure="redirect", redirect_to="/login", include_patterns=['/app', '/admin'],
)
```

With this setup, all requests to `/app` or `/admin` will be authenticated while all other will not. If unauthenticated
user will try to access `/app` it will be redirected to `/login` path.

## Retrieving the authenticated user

You can get currently authenticated user from [user token](user_token.md):

```python
from starlette.responses import PlainTextResponse


def app_view(request):
    user = request.auth.user
    return PlainTextResponse(f'hello {user}!')
```

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
