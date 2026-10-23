"""Configure isolated environment before importing application modules."""
import os
import tempfile
from cryptography.fernet import Fernet

os.environ.setdefault("APP_ENCRYPTION_KEY", Fernet.generate_key().decode())
os.environ.setdefault("ADMIN_API_TOKEN", "test-admin")
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="zabbix-ai-ops-test-"))
os.environ["ALLOW_LEGACY_ADMIN_TOKEN"] = "true"
