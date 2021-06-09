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

FLOW_MANAGER_BYPASS = (b'/account/auth/login', b'/account/auth/register', b'/docs', b'/openapi.json',)
AUTH_SIGN_SECRET = sha512((str(time())+'custom_salt').encode()).hexdigest()
ACCOUNT_SESSION_WHITELIST = ("account_uuid","display_name")

app = Application(show_error_details=True)
post = app.router.post
get = app.router.get
route = app.route
encryption_key = Fernet.generate_key()
app.use_sessions(AUTH_SIGN_SECRET, session_cookie="custom-id", encryptor=FernetEncryptor(encryption_key))
docs = OpenAPIHandler(info=Info(title="Custom Api", version="0.0.0"))
docs.bind_app(app)

async def FlowManager(request, handler):
	"""
	middleware handles:
	* proccess time
	* trace-id
	* client session authentication and
	if it is needed for the endpoint
	"""
	start_time = time()
	bypasses_flow_manager = request.url.value in FLOW_MANAGER_BYPASS
	account_uuid = request.session.get("account_uuid")
	mng_end_time = time()
	if not bypasses_flow_manager and account_uuid is None:
		response = unauthorized({"details": "authentication failed"})
		response.set_header(b"mngr-proccess-time", str(mng_end_time-start_time).encode('latin-1'))
	else:
		response = await handler(request)
		response.set_header(b"mngr-proccess-time", str(mng_end_time-start_time).encode('latin-1'))
	response.set_header(b"trace-id",str(uuid4()).encode('latin-1'))
	end_time = time()
	response.set_header(b"server-proccess-time", str(end_time-start_time).encode('latin-1'))
	return response

app.middlewares.append(FlowManager)