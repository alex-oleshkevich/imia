# User token

A user token is a holder of the request's authentication state. Using user tokens you can get an instance of the current
user, test if the request is authenticated, and get original user details if an impersonation is active.

During request handling the authentication middleware sets user token to `request.auth` making it available in every
view. If the request is not authenticated the anonymous user token is set.

## User token properties

Here is a list of attributes:

* `is_authenticated` returns True if current user is authenticated
* `is_anonymous` returns True if current user is not authenticated
* `original_user_id` returns ID of original user when the impersonation is active
* `scopes` returns list of permissions that current user is assigned
* `user_id` returns ID of current user
* `user` returns a current user instance or instance of `AnonymousUser`
* `display_name` returns a string representation of current user

## Checking if user is authenticated

Use regular if-checks:

```python
if request.auth:
    print('authenticated')
```

## Checking if user has a permission

Leverage "in" operator to check if the user has a specific permission assigned:

```python
if 'auth:impersonate_others' in request.auth:
    print('user can activate impersonation')
```
