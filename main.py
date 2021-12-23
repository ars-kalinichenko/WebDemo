import base64
import hashlib
import hmac
import json
from typing import Optional

from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response

from configs import *

app = FastAPI()


def verify_password(password, hash_value) -> bool:
    return hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower() == hash_value.lower()


def sign_data(data: str) -> str:
    return hmac.new(SECRET_KEY.encode(), msg=data.encode(), digestmod=hashlib.sha256).hexdigest().upper()


def get_user_name_from_signed(username_signed: str) -> Optional[str]:
    user_b64, sign = username_signed.split(".")
    username = base64.b64decode(user_b64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username


@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type="text/html")

    valid_username = get_user_name_from_signed(username)
    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response

    return Response(f"Привет, {users[valid_username]['name']}!", media_type="text/html")


@app.post("/login")
def process_login_page(username: str = Form(...), password: str = Form(...)):
    user = users.get(username)
    if not user or not verify_password(user["password"], password):
        return Response(json.dumps({
            "success": False,
            "message": "Я вас не знаю!"
        }), media_type="text/json")

    response = Response(json.dumps({
        "success": True,
        "message": f"Привет, {user['name']}. <br />Ваш баланс: {user['balance']}"
    }), media_type="text/json")

    cookie_value = base64.b64encode(username.encode()).decode() + "." + sign_data(username)
    response.set_cookie(key="username", value=cookie_value)
    return response
