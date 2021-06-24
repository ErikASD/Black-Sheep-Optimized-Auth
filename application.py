from blacksheep.cookies import Cookie
from blacksheep.server import Application
from blacksheep.server.openapi.v3 import OpenAPIHandler
from blacksheep.server.responses import *
from blacksheep.server.bindings import FromJSON
from blacksheep.messages import Request
from blacksheep.sessions.crypto import FernetEncryptor
from email_validator import validate_email, EmailNotValidError
from openapidocs.v3 import Info
from cryptography.fernet import Fernet
from database.database import SessionLocal
from hashlib import sha512
from uuid import uuid4
import ujson
from time import time
from functools import wraps
from sqlalchemy.sql import exists
import re

SESSION_SIGN_SECRET = sha512((str(time())+'custom_salt').encode()).hexdigest()
ACCOUNT_SESSION_WHITELIST = ("account_uuid","display_name")

app = Application(show_error_details=True)
post = app.router.post
get = app.router.get
route = app.route
encryption_key = Fernet.generate_key()
app.use_sessions(SESSION_SIGN_SECRET, session_cookie="custom-id", encryptor=FernetEncryptor(encryption_key))
docs = OpenAPIHandler(info=Info(title="Custom Api", version="0.0.0"))
docs.bind_app(app)

def session_auth():
	def decorator(next_handler):
		@wraps(next_handler)
		async def wrapped(*args, **kwargs):
			request = args[0]
			try:
				assert request.session.get("account_uuid")
			except:
				response = unauthorized({"details": "authentication failed"})
			else:
				response = await next_handler(*args, **kwargs)
			return response
		return wrapped
	return decorator


def already_signed_in():
	def decorator(next_handler):
		@wraps(next_handler)
		async def wrapped(*args, **kwargs):
			request = args[0]
			try:
				assert not request.session.get("account_uuid")
			except:
				response = forbidden({"already_logged_in_exception": "already logged into "+ request.session.get("display_name")})
			else:
				response = await next_handler(*args, **kwargs)
			return response
		return wrapped
	return decorator