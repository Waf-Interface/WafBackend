from app.auth import hashing
from app.crud import get_user_byUsername
from sqlalchemy.orm import Session


def authenticate_user(db: Session, username: str, password: str):
    user = get_user_byUsername(db, username)
    if not user:
        return None
    if not hashing.verify_password(
        plain_password=password, hashed_password=user.hashed_password
    ):
        return None
    return user
