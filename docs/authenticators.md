# Authenticators

Authenticators are plugins for `imia.AuthenticationMiddleware`. Their purpose is to load user instance from the request.

## Session authenticator

Class: `imia.SessionAuthenticator`

Session authenticator uses session to read authenticated user information. Usually, you need it when you use stateful
login/logout flow.

> **Note**, the authenticator requires session middleware to be activated.

| Option | Type | Description |
|---------|-----|-------------|
|user_provider | UserProvider | A user provider to use.|

## HTTP-Basic authenticator

Class: `imia.HTTPBasicAuthenticator`

Use this class to authenticate users using HTTP-Basic auth.

| Option | Type | Description |
|---------|-----|-------------|
|user_provider | UserProvider | A user provider to use.|
|password_verifier | PasswordVerifier | An instance of [password verifier](./password_verification.md).|

When you add this authenticator you can access protected area by specifying credentials in the request URL:

```shell
curl https://user:password@example.com/app
```

## Token authenticators

Classes: `imia.TokenAuthenticator`

Tokens are a popular way to authenticate API requests. The token is read from the request headers and then challenges
agains the user provider.

| Option | Type | Description |
|---------|-----|-------------|
|user_provider | UserProvider | A user provider to use.|
|token | str | A token type.|

The token type is a part of the headers that goes right before the token value. For example, in header "Authorization:
Bearer TOKENVALUE" the token type is "bearer".

### Usage

```shell
curl -H 'Authorization: Bearer XXXX' https://example.com/app
```

## Bearer token authenticators

Classes: `imia.BearerAuthenticator`

The bearer token is a private case of the token authenticators. The difference between them is
that `BearerAuthenticator`
hardcodes token type to "Bearer"/

| Option | Type | Description |
|---------|-----|-------------|
|user_provider | UserProvider | A user provider to use.|

## API key authenticator

Classes: `imia.APIKeyAuthenticator`

The API key authenticator is similar to token authenticator but obtains API keys from query params or headers.

### Settings

* `user_provider` a user provider to load user instance
* `query_param` (default = "apikey") a query param name that carries key
* `header_name` (default = "X-Api-Key") a header name with a key

| Option | Default | Type | Description |
|---------|--------|------|-------------|
|user_provider | required | UserProvider | A user provider to use.|
|query_param | 'apikey' | str | A name of a query param.|
|header_name | 'X-Api-Key' |  str | A name of a header.|

### Usage

```shell
curl https://example.com/app?apikey=XXXX
# or using headers
curl -H 'X-Api-Key: XXXX' https://example.com/app
```

## Building custom authenticators

Creating own authenticator is pretty simple. Your class has to implement `imia.Authenticator` protocol. For convenience,
you can extend `imia.BaseAuthenticator` abstract class and implement `authenticate(connection)` method.

```python
import typing as t

from imia import UserLike
from starlette.requests import HTTPConnection


class MyAuthenticator:
    async def authenticate(self, connection: HTTPConnection) -> t.Optional[UserLike]:
        return load_user_from_request(connection)
```

## Next topic

Continue to [user tokens](user_token.md).
