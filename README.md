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
- Authentication middleware with fallback strategies (when it cannot authenticate user):
    - redirect to an URL
    - raise an exception
    - do nothing
- [WIP] Remember me
- [WIP] User Impersonation
- [WIP] Two-Factory flow

## Quick start

See example application in `examples/` directory of this repository.
