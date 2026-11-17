import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    mongo_uri: str = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    mongo_db: str = os.getenv("MONGO_DB", "cybershield")
    app_env: str = os.getenv("APP_ENV", "local")
    model_path: str = os.getenv("MODEL_PATH", "/app/models/phish_rf_model.joblib")


settings = Settings()
