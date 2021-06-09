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
			raise Exception({"account_not_found_exception":"account not found"})

	def register(self, request):
		def validate_password():
			if len(self.password) < 9:
				raise Exception({"password_underproduce_exception": "password can not be shorter than 9 characters"})
			elif len(self.password) > 200:
				raise Exception({"password_exceeds_exception": "password can not be longer than 200 characters"})
			for char in self.password:
				int_char = ord(char)
				if not (int_char >= 33 and int_char <= 126):
					raise Exception({"password_out_of_bounds_exception": "password has an invalid char"})
		def validate_format():
			def validate(string_tuple):
				if not string_tuple[1].isalnum():
					raise Exception({"string_invalid_char_exception": f"{string_tuple[0]} has an invalid char"})
				elif len(string_tuple[1]) < 6:
					raise Exception({"string_underproduce_exception": f"{string_tuple[0]} has to be atleast 6 characters"})
				elif len(string_tuple[1]) > 15:
					raise Exception({"string_exceeds_exception": f"{string_tuple[0]} has to be atmost 15 characters"})
			def try_validate_email():
				try:
					valid = validate_email(self.email)
					email = valid.email
				except EmailNotValidError as e:
					raise Exception({"validate_email_exception": str(e)})
			try_validate_email()
			validate(('display_name',self.display_name))

		def exists_then_bad_reqest():
			"""
			if account exists then,
			return bad request 400
			"""
			self.db_account = self.db.query(AccountData.account_uuid).filter(AccountData.email == self.email).one_or_none()
			if self.db_account:
				raise Exception({"duplicate_email_exception":"email already registered"})
			self.db_account = self.db.query(AccountData.account_uuid).filter(AccountData.display_name == self.display_name).one_or_none()
			if self.db_account:
				raise Exception({"duplicate_display_name_exception":"display name already registered"})

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
		validate_format()
		exists_then_bad_reqest()
		self.password = self.input.password
		validate_password()
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
			raise Exception({"wrong_password_exception":"wrong password"})
		raise Exception({"email_not_found_exception":"email not found"})