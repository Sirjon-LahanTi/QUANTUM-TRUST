"""
QuantumTrust Backend — Configuration
"""
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False

    # CORS — allow the Astro dev server
    cors_origins: list[str] = [
        "http://localhost:4321",
        "http://localhost:4322",
        "http://127.0.0.1:4321",
    ]

    # File upload limits
    max_file_size_mb: int = 50

    # Database
    database_url: str = "sqlite+aiosqlite:///./quantumtrust.db"

    class Config:
        env_file = ".env"
        env_prefix = "QT_"


settings = Settings()
