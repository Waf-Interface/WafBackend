from typing import Optional
from pydantic import BaseModel, Field


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
    id: int = Field(
        ..., description="The unique identifier"
    )
