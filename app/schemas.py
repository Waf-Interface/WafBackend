from typing import Optional
from pydantic import BaseModel, Field

from app.enums.user_roles import UserRole


class LoginRequest(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str = Field(..., description="The access token")
    token_type: str = Field(..., description="The type of the token")


class TokenData(BaseModel):
    # username: Optional[str] = Field(
    #     None, description="The username"
    # )
    # role: Optional[UserRole] = Field(
    #     None, description="The user's role"
    # )
    id: int = Field(..., description="The unique identifier")


class UserBase(BaseModel):
    username: str = Field(
        ...,
        description="The user's unique username",
    )
    # name: str = Field(
    #     ..., description="The user's first name"
    # )
    # last_name: str = Field(
    #     ..., description="The user's last name"
    # )
    # phone_number: str = Field(
    #     ...,
    #     description="The user's contact number",
    # )


class UserIn(UserBase):
    password: str = Field(..., description="The user's password")


class UserOut(UserBase):
    id: int = Field(..., description="The user's unique identifier")
    # TODO admin?
    # role: UserRole = Field(..., examples=[], description="The user's role")

    class Config:
        from_attributes = True


class UserOut_withPassword(UserOut):
    hashed_password: str = Field(
        ...,
        description="The user's hashed password",
    )
