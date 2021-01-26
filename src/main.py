from datetime import datetime, timedelta
from typing import List, Optional
import logging

import uvicorn
from fastapi import Depends, FastAPI, Query, HTTPException, Request, Security, status
from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
    SecurityScopes,
)
import httpx
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, ValidationError
import json
from settings import settings

fake_users_db = {
    "bart": {
        "username": "bart",
        "full_name": "Bart",
        "email": "bart@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
        "scopes": ["BRK/RS", "BRK/RO", "BRK/RSN"]

    }
}

log = logging.getLogger(__name__)


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None
    scopes: List[str] = []


class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None
    scopes:List[str]


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    scopes={
        "me": "Read information about the current user.",
        "items": "Read items.",
        "BRK/RO": "BRK Read Object",
        "BRK/RS": "BRK Read Subject",
        "BRK/RSN": "BRK Read Natural Subject",
    },
)

app = FastAPI()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode, settings.secret_key, algorithm=settings.algorithm
    )
    return encoded_jwt


async def get_current_user(
    security_scopes: SecurityScopes, token: str = Depends(oauth2_scheme)
):
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else:
        authenticate_value = f"Bearer"
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": authenticate_value},
    )
    try:
        payload = jwt.decode(
            token, settings.secret_key, algorithms=[settings.algorithm]
        )
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_scopes = payload.get("scopes", [])
        token_data = TokenData(scopes=token_scopes, username=username)
    except (JWTError, ValidationError):
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": authenticate_value},
            )
    return user


async def get_current_active_user(
    current_user: User = Security(get_current_user, scopes=["me"])
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    scopes = list(set(user.scopes) & set(form_data.scopes))
    access_token = create_access_token(
        data={"sub": user.username, "scopes": scopes},
        expires_delta=access_token_expires,
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(
    current_user: User = Security(get_current_active_user, scopes=["items"])
):
    return [{"item_id": "Foo", "owner": current_user.username}]


@app.get("/gettest")
async def gettest():
    async with httpx.AsyncClient() as client:
        response = await client.get("http://httpbin.org/uuid")
        json_obj = json.loads(response.read().decode("utf-8"))
        return json_obj["uuid"]


def get_headers(request: Request):
    client_ip = request.headers.get("REMOTE_ADDR")
    if isinstance(client_ip, str):
        client_ip = client_ip.encode("iso-8859-1")
    forward = request.headers.get("HTTP_X_FORWARDED_FOR", "")
    if forward:
        if isinstance(forward, str):
            forward = forward.encode("iso-8859-1")
        forward = b"%b %b" % (forward, client_ip)
    else:
        forward = client_ip

    headers = {
        "Accept": "application/hal+json; charset=utf-8",
        "X-Api-Key": settings.haal_centraal_api_key,
        "Accept-Crs": "epsg:28992",
    }
    if forward:
        headers["X-Forwarded-For"] = forward

    # We check if we already have a X-Correlation-ID header
    x_correlation_id = request.headers.get("HTTP_X_CORRELATION_ID")
    if x_correlation_id:
        # And if defined pass on to the destination
        headers["X-Correlation-ID"] = x_correlation_id.encode("iso-8859-1")

    return headers


BASE_URL = "https://api.brk.acceptatie.kadaster.nl/esd/bevragen/v1"




@app.get("/hcproxy/brk/kadastraalonroerendezaken")
async def get_kadastraalonroerendezaken(
    request: Request,
    current_user: User = Security(get_current_user, scopes=["BRK/RO"]),
    postcode: Optional[str] = Query(
        None, min_length=6, max_length=6, regex=r"^\d{4}[A-Za-z]{2}$"
    ),
):
    log.warning(f"User {current_user.username} requested {request.url}")
    headers = get_headers(request)
    parameters = {}
    if postcode:
        parameters["postcode"] = postcode

    url = f"{BASE_URL}/kadastraalonroerendezaken"

    async with httpx.AsyncClient(headers=headers) as client:
        response = await client.get(url, params=parameters)
        json_obj = json.loads(response.read().decode("utf-8"))
        return json_obj


@app.get("/hcproxy/brk/kadasternatuurlijkpersonen")
async def kadasternatuurlijkpersonen(
    request: Request,
    current_user: User = Security(get_current_user, scopes=["BRK/RSN"]),
    q: Optional[str] = Query(
        None, min_length=3, max_length=100
    ),
):
    log.warning(f"User {current_user.username} requested {request.url}")
    headers = get_headers(request)
    parameters = {}
    if q:
        parameters["q"] = q

    url = f"{BASE_URL}/kadasternatuurlijkpersonen"

    async with httpx.AsyncClient(headers=headers) as client:
        response = await client.get(url, params=parameters)
        json_obj = json.loads(response.read().decode("utf-8"))
        return json_obj


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
