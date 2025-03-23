from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "sqlite:///./users.db"
ACCESS_DB_URL = "sqlite:///./access.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
access_engine = create_engine(ACCESS_DB_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
AccessSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=access_engine)

Base = declarative_base()
AccessBase = declarative_base()
