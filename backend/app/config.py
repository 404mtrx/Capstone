from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = (
        "postgresql+psycopg2://sentinel:sentinel_dev_pw@localhost:5432/sentinelwatch"
    )
    opensearch_url: str = "http://localhost:9200"
    opensearch_index: str = "sentinel-events"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
