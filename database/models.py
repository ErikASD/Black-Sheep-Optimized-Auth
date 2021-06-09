from sqlalchemy import Column, Integer, String, Text, Boolean, Float, ForeignKey
from database.database import Base, engine


class AccountData(Base):
    __tablename__ = "Account_data"

    account_uuid = Column(String(36), unique=True, nullable=False, primary_key=True, index=True)
    display_name = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False, index=True)
    password = Column(String(100), nullable=False)
    salt = Column(String(10), nullable=False)
    account_type = Column(Integer, nullable=False, index=True)
    time_stamp_created = Column(Integer, nullable=False, index=True)

Base.metadata.create_all(bind=engine)