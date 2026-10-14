from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = (
        "postgresql+psycopg2://sentinel:sentinel_dev_pw@localhost:5432/sentinelwatch"
    )

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
