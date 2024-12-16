from sqlalchemy.orm import Session
from app import models, schemas


def get_user_byId(db: Session, id: int) -> schemas.UserOut_withPassword | None:
    return db.query(models.User).filter(models.User.id == id).first()


def get_user_byUsername(
    db: Session, username: str
) -> schemas.UserOut_withPassword | None:
    return db.query(models.User).filter(models.User.username == username).first()
