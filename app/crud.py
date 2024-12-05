from sqlalchemy.orm import Session
from app import models, schemas


def get_user_byId(db: Session, id: int):
    return db.query(models.User).filter(models.User.id == id).first()
