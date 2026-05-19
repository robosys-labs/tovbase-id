from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "sqlite:///./data/tovbase_id.db"
    did_method: str = "tov"
    did_node_id: str = "tovbase-id-dev-1"
    did_signing_key_id: str = "tovbase-registry-dev-1"
    did_signing_private_key_b64: str = ""
    did_verifying_keys_json: str = ""
    trusted_bank_keys_json: str = ""
    registry_publication_name: str = "did_registry_publication"
    action_challenge_ttl_seconds: int = 300

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
