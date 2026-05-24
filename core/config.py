"""
R&D: OmniaGuard Configuration
===============================
Environment-based configuration for the OmniaGuard security platform.

All secrets loaded from .env file (never committed to git).
Validated at startup — fails fast if required vars are missing.
"""

import os
from dataclasses import dataclass, field
from typing import Optional
from dotenv import load_dotenv

load_dotenv()


@dataclass
class Config:
    """OmniaGuard platform configuration."""

    # --- Telegram Bot ---
    telegram_bot_token: str = field(
        default_factory=lambda: os.getenv("TELEGRAM_BOT_TOKEN", "")
    )
    telegram_admin_chat_id: str = field(
        default_factory=lambda: os.getenv("TELEGRAM_ADMIN_CHAT_ID", "")
    )

    # --- Supabase ---
    supabase_url: str = field(
        default_factory=lambda: os.getenv("SUPABASE_URL", "")
    )
    supabase_anon_key: str = field(
        default_factory=lambda: os.getenv("SUPABASE_ANON_KEY", "")
    )
    supabase_service_key: str = field(
        default_factory=lambda: os.getenv("SUPABASE_SERVICE_KEY", "")
    )

    # --- Together AI ---
    together_api_key: str = field(
        default_factory=lambda: os.getenv("TOGETHER_API_KEY", "")
    )
    together_model: str = field(
        default_factory=lambda: os.getenv(
            "TOGETHER_MODEL", "meta-llama/Llama-3.1-70B-Instruct-Turbo"
        )
    )
    together_fast_model: str = field(
        default_factory=lambda: os.getenv(
            "TOGETHER_FAST_MODEL", "meta-llama/Llama-3.1-8B-Instruct-Turbo"
        )
    )

    # --- Domain ---
    domain: str = field(
        default_factory=lambda: os.getenv("DOMAIN", "omniaguard.com")
    )
    api_base_url: str = field(
        default_factory=lambda: os.getenv("API_BASE_URL", "https://api.omniaguard.com")
    )

    # --- Agent Settings ---
    scan_interval_minutes: int = field(
        default_factory=lambda: int(os.getenv("SCAN_INTERVAL_MINUTES", "60"))
    )
    alert_threshold: str = field(
        default_factory=lambda: os.getenv("ALERT_THRESHOLD", "medium")
    )
    max_concurrent_scans: int = field(
        default_factory=lambda: int(os.getenv("MAX_CONCURRENT_SCANS", "5"))
    )

    def validate(self) -> list[str]:
        """Check all required vars are set. Returns list of missing vars."""
        required = [
            ("TELEGRAM_BOT_TOKEN", self.telegram_bot_token),
            ("SUPABASE_URL", self.supabase_url),
            ("SUPABASE_SERVICE_KEY", self.supabase_service_key),
            ("TOGETHER_API_KEY", self.together_api_key),
        ]
        return [name for name, val in required if not val]


config = Config()
