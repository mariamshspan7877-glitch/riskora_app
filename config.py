import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, ".env"))


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-riskora-secret")
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{os.path.join(basedir, 'instance', 'riskora.db')}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_UPLOAD_SIZE = int(os.getenv("MAX_CONTENT_LENGTH", "16777216"))
    MAX_CONTENT_LENGTH = MAX_UPLOAD_SIZE + (64 * 1024)
    UPLOAD_FOLDER = os.path.join(basedir, "uploads")
    REPORT_FOLDER = os.path.join(basedir, "reports")
    GCP_PROJECT_ID = os.getenv("GCP_PROJECT_ID")
    GCS_BUCKET_NAME = os.getenv("GCS_BUCKET_NAME")
    WTF_CSRF_TIME_LIMIT = 3600
