from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = (
        "postgresql+psycopg2://sentinel:sentinel_dev_pw@localhost:5432/sentinelwatch"
    )
    opensearch_url: str = "http://localhost:9200"
    opensearch_index: str = "sentinel-events"
    # OpenSearch login. Leave the user empty only for an unsecured local OpenSearch.
    opensearch_user: str = ""
    opensearch_password: str = ""
    # The demo certificate that OpenSearch makes for itself is self-signed, so checking it
    # fails. Keep False for local development; set True and give a CA file for real use.
    opensearch_verify_certs: bool = False
    opensearch_ca_certs: str = ""

    # Authentication. Set AUTH_REQUIRED=false in .env to turn it off for a demo.
    auth_required: bool = True
    secret_key: str = "dev-only-change-me"  # sign tokens; set a long random value in .env
    access_token_minutes: int = 60
    api_key: str = ""  # shared key for the collector and detection engine (X-API-Key)

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
