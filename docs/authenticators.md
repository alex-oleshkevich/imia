# Authenticators

An authenticator is a plugin for `imia.AuthenticationMiddleware`. It's purpose is to load user instance from the
request.

## Session authenticator

Session authenticator uses session to read authenticated user information. Usually, you need it when you use stateful
login/logout flow.

**Note**, the authenticator requires session to be available.

### Settings

* `user_provider` a user provider to load user instance

## HTTP-Basic authenticator

Use this class to authenticate users using HTTP-Basic auth.

### Settings

* `user_provider` a user provider to load user instance
* `password_verifier` to check user password

Now you can access protected area by specifying credentials in the request URL:

```shell
curl https://user:password@example.com/app
```

## Token (and Bearer token) authenticators

Token, and it's specific case, Bearer token, is a popular approach to authenticate API requests.

### Settings

* `user_provider` a user provider to load user instance
* `token` a token name (a string that goes before the actual value in the Authorization header)

For example in header string `Authorization: Bearer XXXXXX` a token name is "Bearer".

For bearer tokens there is a convenience authenticator `imia.BearerAuthenticator`
that sets up the header name for you.

### Usage

```shell
curl -H 'Authorization: Bearer XXXX' https://example.com/app
```

## API key authenticator

This one is similar to the token authenticator but reads API key from query params or headers.

### Settings

* `user_provider` a user provider to load user instance
* `query_param` (default = "apikey") a query param name that carries key
* `header_name` (default = "X-Api-Key") a header name with a key

### Usage

```shell
curl https://example.com/app?apikey=XXXX
# or using headers
curl -H 'X-Api-Key: XXXX' https://example.com/app
```

## Custom authenticator

Creating own authenticator is pretty simple. Your class has to implement `imia.Authenticator` protocol. For convenience,
you can extend `imia.BaseAuthenticator` abstract class.

```python
import typing as t

from imia import UserLike
from starlette.requests import HTTPConnection


class MyAuthenticator:
    async def authenticate(self, connection: HTTPConnection) -> t.Optional[UserLike]:
        return load_user_from_request(connection)
```
