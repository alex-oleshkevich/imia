# Imia

Imia (belarussian for "a name") is an authentication library for Starlette and FastAPI (python 3.8+).

![PyPI](https://img.shields.io/pypi/v/imia)
![GitHub Workflow Status](https://img.shields.io/github/workflow/status/alex-oleshkevich/imia/Lint)
![GitHub](https://img.shields.io/github/license/alex-oleshkevich/imia)
![Libraries.io dependency status for latest release](https://img.shields.io/librariesio/release/pypi/imia)
![PyPI - Downloads](https://img.shields.io/pypi/dm/imia)
![GitHub Release Date](https://img.shields.io/github/release-date/alex-oleshkevich/imia)
![Lines of code](https://img.shields.io/tokei/lines/github/alex-oleshkevich/imia)

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

## Quick start

If you are too lazy to read this doc, take a look into `examples/` directory. There you will find several files demoing
various parts of this library.

## Docs

1. [Configuration](docs/configuration.md)
2. [Login/Logout flow](docs/login_logout.md)
3. [User token](docs/user_token.md)
4. [Request authentication](docs/authentication.md)
5. [Authenticators](docs/authenticators.md)
6. [User impersontation](docs/impersonation.md)

## Usage

See [examples/](examples) directory.
