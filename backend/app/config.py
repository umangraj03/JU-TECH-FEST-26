import os
from pathlib import Path
from pydantic import BaseModel
from dotenv import load_dotenv

# Find root .env
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
env_path = ROOT_DIR / ".env"
if env_path.exists():
    load_dotenv(env_path)
else:
    load_dotenv()


class Settings(BaseModel):
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "8000"))
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    DEMO_MODE: bool = os.getenv("DEMO_MODE", "true").lower() in ("true", "1", "yes")

    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{ROOT_DIR / 'security_guard.db'}")
    SANDBOX_DIR: str = os.getenv("SANDBOX_DIR", str(ROOT_DIR / "sandbox_storage"))
    POLICY_FILE: str = str(ROOT_DIR / "policies" / "default.yaml")

    TOKEN_REQUESTER: str = os.getenv("TOKEN_REQUESTER", "token-requester-secret-key-101")
    TOKEN_APPROVER: str = os.getenv("TOKEN_APPROVER", "token-approver-secret-key-202")
    TOKEN_ADMIN: str = os.getenv("TOKEN_ADMIN", "token-admin-secret-key-303")

    APPROVAL_TIMEOUT_SECONDS: int = int(os.getenv("APPROVAL_TIMEOUT_SECONDS", "900"))
    MAX_EGRESS_BYTES_PER_SESSION: int = int(os.getenv("MAX_EGRESS_BYTES_PER_SESSION", "5000"))
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))


settings = Settings()

PRINCIPAL_MAP = {
    settings.TOKEN_REQUESTER: {"principal_id": "user_requester", "role": "requester", "name": "Requester User"},
    settings.TOKEN_APPROVER: {"principal_id": "user_approver", "role": "approver", "name": "Security Approver"},
    settings.TOKEN_ADMIN: {"principal_id": "user_admin", "role": "admin", "name": "System Administrator"},
}
