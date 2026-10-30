"""Creates backend/.env with fresh random secrets (never overwrites an existing .env).

Run from the backend folder:   python -m scripts.generate_env
"""
import secrets
from pathlib import Path

from cryptography.fernet import Fernet

ENV_PATH = Path(".env")
EXAMPLE_PATH = Path(".env.example")


def main() -> None:
    if ENV_PATH.exists():
        print(".env already exists. Nothing changed. Delete it first if you really want new secrets.")
        return
    text = EXAMPLE_PATH.read_text(encoding="utf-8")
    text = text.replace("SECRET_KEY=\n", f"SECRET_KEY={secrets.token_urlsafe(64)}\n", 1)
    text = text.replace("TOTP_ENCRYPTION_KEY=\n", f"TOTP_ENCRYPTION_KEY={Fernet.generate_key().decode()}\n", 1)
    ENV_PATH.write_text(text, encoding="utf-8")
    print("Created .env with new random secrets. Keep it private and never commit it.")


if __name__ == "__main__":
    main()
