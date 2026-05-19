from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "sqlite:///./data/tovbase_id.db"
    did_method: str = "tov"
    did_node_id: str = "tovbase-id-dev-1"
    did_signing_key_id: str = "tovbase-registry-dev-1"
    did_signing_private_key_b64: str = ""
    did_verifying_keys_json: str = ""
    bank_api_keys_json: str = ""
    admin_api_keys_json: str = ""
    trusted_bank_keys_json: str = ""
    trusted_attestation_provider_keys_json: str = ""
    registry_publication_name: str = "did_registry_publication"
    nats_url: str = "nats://127.0.0.1:4222"
    nats_stream_name: str = "TOVBASE_ID_REGISTRY"
    nats_subject_prefix: str = "tovbase.id.registry"
    action_challenge_ttl_seconds: int = 300
    access_log_enabled: bool = True

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
