# UserLike object (the user model)

As this library does not depend on any specific implementation of user model, it cannot know the structure of the class
that you are going to use as a user representation. To solve this problem we define
a [protocol](https://www.python.org/dev/peps/pep-0544/) named `UserLike` that describes an expected shape of the user model. You,
as a library user have to define it before you can use this library.

## UserLike protocol

Here is the list of methods that your user model should implement:

* `def get_display_name(self) -> str` returns a string representation of user. Usually a full name.
* `def get_id(self) -> typing.Any` returns ID of user.
* `def get_hashed_password(self) -> str` returns a hashed password string
* `def get_scopes(self) -> list[str]` returns list of permission scopes. Access control libraries may use it to check
  permissions.

A very basic user model can look like this one:

```python
import dataclasses
import typing as t


@dataclasses.dataclass()
class User:
    id: str
    name: str
    email: str
    password: str
    scopes: list[str]
    api_token: str = None

    def get_display_name(self) -> str:
        return self.name

    def get_id(self) -> t.Any:
        return self.id

    def get_hashed_password(self) -> str:
        return self.password

    def get_scopes(self) -> list[str]:
        return self.scopes
```

> You are not limited to dataclasses. You can implpement these methods on any python class and library will accept it.

The next concept is [user providers](user_providers.md)
