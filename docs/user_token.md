# User token

The authentication middleware sets a special variable named *user token* into the request. User token contains meta
information about current user. You can use it to check if the user is authenticated, get user permissions, and other
data. The user token available in `request.auth`.

Here is a list of attributes:

* `is_authenticated` returns True if current user is not anonymous
* `is_anonymous` returns True if current user is anonymous
* `original_user_id` returns ID of original user when the inpersonation session is active
* `scopes` returns list of permissions that current user has
* `user_id` returns ID of current user
* `user` returns a current user instance
* `display_name` returns a string representation of current user

A special shortcut methods available:

* `permission' in request.auth` to check if user has a specific permission
* `if request.auth: ...` to check if user is authenticated
