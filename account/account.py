from application import *
from database.models import AccountData
from database.database import SessionLocal
import uuid
from hashlib import sha256, sha512
import time

class Account:
	def __init__(self, request):
		self.db = SessionLocal()
		self.request = request

	@staticmethod
	def exists_or_not_found(email, db):
		"""
		if account does not exists then,
		return bad request 400
		"""
		self.db_account = self.db.query(AccountData.account_uuid).filter(AccountData.email == email).one_or_none()
		if self.db_account is None:
			return bad_request({"account_not_found_exception":"account not found"})

	def register(self, request):
		def validate_inputs():
			exception, reason = validate_data()
			response = ok()
			if exception != 'success':
				response = bad_request({exception:reason})
			return response

		def validate_data():
			if len(self.password) < 9 or len(self.password) > 200:
				return ("password_length_exception", "password can not be shorter than 9 characters or longer than 200")
			elif self.password.isalnum():
				return ("password_special_char_missing_exception", "password is missing a special character")
			elif not self.display_name.isalnum():
				return ("string_invalid_char_exception", "display_name has an invalid char")
			elif len(self.display_name) < 6:
				return ("string_underproduce_exception", "display_name has to be atleast 6 characters")
			elif len(self.display_name) > 15:
				return ("string_exceeds_exception", "display_name has to be atmost 15 characters")
			try:
				valid = validate_email(self.email)
				email = valid.email
			except EmailNotValidError as e:
				return ("validate_email_exception", str(e))
			for char in self.password:
				int_char = ord(char)
				if not (int_char >= 33 and int_char <= 126):
					return ("password_out_of_bounds_exception", "password has an invalid char")
			self.db_account = self.db.query(AccountData.account_uuid).filter(AccountData.email == self.email).one_or_none()
			if self.db_account:
				return ("duplicate_email_exception", "email already registered")
			self.db_account = self.db.query(AccountData.account_uuid).filter(AccountData.display_name == self.display_name).one_or_none()
			if self.db_account:
				return ("duplicate_display_name_exception", "display name already registered")
			return ("success","success")

		def generate_uuid() -> str:
			"""
			generates unique identifier
			"""
			return str(uuid.uuid4())

		def generate_salt() -> str:
			"""
			to make the hashed password secure
			in case of a databreach, makes it
			close to imposible for a dictionary
			attack to occur
			"""
			return str(uuid.uuid4())[:12]

		def hashed_password(password, salt) -> str:
			"""
			hashes the user given password
			with salt for maximum security
			"""
			return sha512((password+salt).encode("utf-8")).hexdigest()

		self.input = request.value
		self.email = self.input.email.lower()
		self.display_name = self.input.display_name.lower()
		self.password = self.input.password
		response = validate_inputs()
		if response.status != 200:
			return response
		self.salt = generate_salt()
		self.uuid = generate_uuid()
		self.hashed_password = hashed_password(self.password, self.salt)
		self.time = int(time.time())

		self.db_account = AccountData(
			account_uuid = self.uuid,
			email = self.email,
			password = self.hashed_password,
			display_name = self.display_name,
			salt = self.salt,
			account_type = 0,
			time_stamp_created = self.time,
			)
		self.db.add(self.db_account)
		self.db.commit()
		self.db.refresh(self.db_account)
		for attribute in self.db_account.__dict__:
			if not attribute.startswith('_'):
				self.request.session[attribute] = self.db_account.__dict__[attribute]
		return ok({"uuid": self.uuid})


	def login(self, request):
		def compare_password(password, salt) -> str:
			"""
			tests the user entered password combined with the salt
			to see if the one on db's password and entered password are
			the exact same
			"""
			return sha512((password + salt).encode("utf-8")).hexdigest()
		self.input = request.value
		self.email = self.input.email.lower()
		self.password = self.input.password

		self.db_account = self.db.query(AccountData.account_uuid, AccountData.password, AccountData.salt).filter(AccountData.email == self.email).one_or_none()
		if self.db_account:
			self.uuid = self.db_account[0]
			if self.db_account[1] == compare_password(self.password, self.db_account[2]):
				for attribute in self.db_account.keys():
					if not attribute.startswith('_'):
						self.request.session[attribute] = self.db_account[attribute]
				return ok({"uuid": self.uuid})
			return bad_request({"wrong_password_exception":"wrong password"})
		return bad_request({"email_not_found_exception":"email not found"})