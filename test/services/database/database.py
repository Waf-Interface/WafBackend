from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "sqlite:///./users.db"
ACCESS_DB_URL = "sqlite:///./access.db"
INTERFACE_DB_URL = "sqlite:///./interface.db"
WEBSITE_DB_URL = "sqlite:///./website.db"  

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
access_engine = create_engine(ACCESS_DB_URL, connect_args={"check_same_thread": False})
interface_engine = create_engine(INTERFACE_DB_URL, connect_args={"check_same_thread": False})
website_engine = create_engine(WEBSITE_DB_URL, connect_args={"check_same_thread": False})  

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
AccessSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=access_engine)
InterfaceSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=interface_engine)
WebsiteSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=website_engine)  

Base = declarative_base()
AccessBase = declarative_base()
InterfaceBase = declarative_base()
WebsiteBase = declarative_base()  