from dataclasses import dataclass
from database.models import AccountData
from account.account import Account
from application import *

@dataclass
class RegisterDataClass:
    email: str
    password: str
    display_name: str

@dataclass
class LoginDataClass:
    email: str
    password: str

@post("/account/auth/login")
@already_signed_in()
async def api_account_auths_login(request: Request, login: FromJSON[LoginDataClass]):
    """
    checks if params match account details
    @params LoginDataClass
    email: str
    password: str
    """
    response = Account(request).login(login)
    return response

@post("/account/auth/register")
@already_signed_in()
async def api_account_auth_register(request: Request, register: FromJSON[RegisterDataClass]):
    """
    creates account
    @params RegisterDataClass
    display_name: str
    email: str
    password: str
    """
    response = Account(request).register(register)
    return response

@get("/account/auth/session")
@session_auth()
async def api_account_auth_session(request):
    """
    checks if the session 
    cookie is valid
    """
    iter_dict = request.session._values
    account_session = {}
    for keys in iter_dict.keys():
        if keys in ACCOUNT_SESSION_WHITELIST:
            account_session.update({keys:iter_dict[keys]})

    response = ok(account_session)
    return response