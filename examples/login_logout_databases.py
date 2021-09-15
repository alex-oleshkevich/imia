"""
following is requirements.txt
============
starlette
sqlalchemy
databases[sqlite]
uvicorn
imia
passlib
sqlalchemy_utils
============
"""

import dataclasses
from dataclasses import dataclass
import pathlib
import typing as t

import databases
import sqlalchemy
from sqlalchemy import create_engine, select
from sqlalchemy_utils import database_exists, create_database
from passlib.hash import pbkdf2_sha1, pbkdf2_sha256
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.routing import Route
from starlette.config import Config
from imia import AuthenticationMiddleware, InMemoryProvider, LoginManager, SessionAuthenticator
from imia import UserProvider, UserLike


config = Config('.env')
DATABASE_URL = config('DATABASE_URL')

metadata = sqlalchemy.MetaData()

# Definining data base schema
users = sqlalchemy.Table(
    "users",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("fullname", sqlalchemy.Unicode),
    sqlalchemy.Column("email", sqlalchemy.Unicode),
    sqlalchemy.Column("hashed_password", sqlalchemy.Unicode),
    sqlalchemy.Column("completed", sqlalchemy.Boolean),
)

db = databases.Database(DATABASE_URL)

# Create tables if database does not exists. This should be done using alembic in production.
def create_tables():
    if not database_exists(DATABASE_URL):
        engine = create_engine(DATABASE_URL)
        metadata.create_all(engine)

# Populating some users in the table
async def create_users():
    query = "INSERT INTO users(fullname, email, hashed_password) VALUES (:fullname, :email, :hashed_password)"
    values = [
        {"fullname": "Alpha Beta", "email": "alpha@mail.com", "hashed_password": pbkdf2_sha256.encrypt("Beta")},
        {"fullname": "Theta Gamma", "email": "theta@mail.com", "hashed_password": pbkdf2_sha256.encrypt("Gamma")},
    ]
    await db.execute_many(query=query, values=values)


# Create datastructure for loading the user from database. Like a bridge class for UserLike protocol.
@dataclass
class User:
    """This is our user model. Any user model must implement UserLike protocol."""

    id: str
    fullname: str
    email: str
    hashed_password: str
    scopes: list[str] = dataclasses.field(default_factory=list)
    #api_token: str= None

    def get_display_name(self):
        return self.fullname

    def get_id(self):
        return self.id

    def get_hashed_password(self):
        return self.hashed_password

    def get_scopes(self):
        return self.scopes

# Create an UserProvider ie Storage talking utitly. Because the sqlalchemy core does not directly provide UserLike protocol adaptation, we are using User dataclass as the adapter for providing UserLike implementation over the sqlahcemy model. I know, this might be an overkill but thats how it is implemented now. Once we get better knowedge of sqlchemy core, this adapter will be no longer necessary.t
class CustomUserProvider(UserProvider):
    async def find_by_id(self, id: t.Any) -> t.Optional[UserLike]:
        """Load user by user ID."""
        stmt = select(users).where(users.c.id == id)
        user_row = await db.fetch_one(stmt)
        user = User(id=user_row[0], fullname=user_row[1], email=user_row[2], hashed_password=user_row[3], scopes=[])
        return user

    async def find_by_username(self, username_or_email: str) -> t.Optional[UserLike]:
        """Load user by username or email."""
        stmt = select(users).where(users.c.email == username_or_email)
        user_row = await db.fetch_one(stmt)
        user = User(id=user_row[0], fullname=user_row[1], email=user_row[2], hashed_password=user_row[3], scopes=[])
        return user

    async def find_by_token(self, token: str) -> t.Optional[UserLike]:
        """Load user by token."""
        for user in _users:
            if user.api_token == token:
                return user


secret_key = 'key!'
"""For security!"""

#user_provider = InMemoryProvider({'root@localhost': User()})
user_provider = CustomUserProvider()
"""The class that looks up for a user. you may provide your own for, eg. database user lookup"""

password_verifier = pbkdf2_sha256
"""Password checking tool. Password checkers must match PasswordVerifier protocol."""

login_manager = LoginManager(user_provider, password_verifier, secret_key)
"""This is the core class of login/logout flow"""


def index_view(request: Request) -> HTMLResponse:
    """Display welcome page."""
    return HTMLResponse("""<a href="/login">Login</a> | <a href="/app">P1</a> """)


async def login_view(request: Request):
    """Display login page  and handle login POST request."""
    error = ''
    if 'error' in request.query_params:
        error = '<span style="color:red">invalid credentials</span>'
    if request.method == 'POST':
        form = await request.form()
        email = form['email']
        password = form['password']

        print(request, email, password)
        user_token = await login_manager.login(request, email, password)
        if user_token:
            return RedirectResponse('/app', status_code=302)
        return RedirectResponse('/login?error=invalid_credentials', status_code=302)
    return HTMLResponse(
        """
    %s
    <form method="post">
    <label>email <input name="email" value="alpha@mail.com"></label>
    <label>password <input name="password" type="password" value="Beta"></label>
    <button type="submit">submit</button>
    </form>
    """
        % error
    )

async def logout_view(request: Request) -> RedirectResponse:
    """Handle logout request."""
    if request.method == 'POST':
        await login_manager.logout(request)
        return RedirectResponse('/login', status_code=302)
    return RedirectResponse('/app', status_code=302)


async def app_view(request: Request) -> HTMLResponse:
    """This is our protected area. Only authorized users allowed."""
    user = request.auth.display_name
    return HTMLResponse(
        """
        Hi %s! This is protected 1 app area.
        <form action="/logout" method="post">
        <button>logout</button>
        </form>
        """
        % user
    )


app = Starlette(
    debug=True,
    routes=[
        Route('/', index_view),
        Route('/login', login_view, methods=['GET', 'POST']),
        Route('/logout', logout_view, methods=['POST']),
        Route('/app', app_view),
    ],
    middleware=[
        Middleware(SessionMiddleware, secret_key=secret_key),
        Middleware(
            AuthenticationMiddleware,
            authenticators=[SessionAuthenticator(user_provider)],
            on_failure='redirect',
            redirect_to='/login',
            include_patterns=[r'\/app']
            # protect /app path
        ),
    ],
    on_startup=[create_tables, create_users, db.connect],
    on_shutdown=[db.disconnect],
)
