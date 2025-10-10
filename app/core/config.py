# app/core/config.py
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://nyfong:fongfong@localhost:5432/postgres"
    
    # Keycloak settings
    keycloak_url: str = "http://localhost:1920/realms/fastapi-realm"
    keycloak_client_id: str = "fastapi-client"
    keycloak_admin_username: str = "fongko"
    keycloak_admin_password: str = "kdetkdetkdet"
    keycloak_admin_url: str = "http://localhost:1920/admin"
    keycloak_client_secret: str = "KtUZrEEPaDsGzaGBQ3qxPPejvr7ZfKQ1"
    keycloak_realm_name: str = "fastapi-realm"
    redirect_uri: str = "http://localhost:1920/auth/callback"
    
    # Sonarqube settings
    sonar_token: str = "sqa_8d5718e6d228fcfd733225718448da5f5e5642cb"
    
    # Use SettingsConfigDict for Pydantic v2 configuration
    model_config = SettingsConfigDict(env_file=".env", extra="allow")

settings = Settings()
