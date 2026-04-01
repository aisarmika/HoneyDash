from pathlib import Path

from pydantic_settings import BaseSettings

# Resolve paths relative to this file so they work regardless of
# which directory uvicorn is launched from.
_HERE = Path(__file__).parent


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://honeydash:honeydash_pass@localhost:5432/honeydash"
    cowrie_log_path: str = str(_HERE / "cowrie.json")
    virustotal_api_key: str = ""
    secret_key: str = "change-this-to-a-random-secret-in-production"
    admin_email: str = "admin@honeydash.local"
    admin_password_hash: str = ""
    log_catchup_on_start: bool = False
    vt_rate_limit_seconds: float = 15.0
    enrichment_cache_hours: int = 24

    model_config = {"env_file": str(_HERE / ".env")}


settings = Settings()
