from fastapi import FastAPI
from app.database import engine
from app.routers import waf
from app import models


models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Waf",
    # description="",
    version="1.0.0",
    # terms_of_service="http://example.com/terms/",
    # contact={
    #     "name": "Support Team",
    #     "url": "http://example.com/contact/",
    #     "email": "ehsan.moradi.it@gmail.com",
    # },
    # license_info={
    #     "name": "Apache 2.0",
    #     "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
    # },
)

app.include_router(waf.router)

