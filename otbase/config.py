import os
from pathlib import Path
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent
DEFAULT_DATA_DIR = PROJECT_DIR / "data"
DEFAULT_STATIC_DIR = BASE_DIR / "web" / "static"

class Settings(BaseModel):
    app_name: str = "OT-BASE Asset Center"
    app_version: str = "1.0.0"
    debug: bool = False
    host: str = os.getenv("OTBASE_HOST", "0.0.0.0")
    port: int = int(os.getenv("OTBASE_PORT", "8000"))
    data_dir: Path = DEFAULT_DATA_DIR
    static_dir: Path = DEFAULT_STATIC_DIR

settings = Settings()

# Ensure data directory exists
settings.data_dir.mkdir(parents=True, exist_ok=True)
