"""Configuration helpers with a small dependency-free .env loader."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def load_dotenv(path: str | Path = ".env") -> None:
    """Load simple KEY=VALUE entries without replacing existing variables."""
    env_path = Path(path)
    if not env_path.is_file():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            os.environ.setdefault(key, value)


@dataclass(frozen=True)
class Settings:
    abuseipdb_api_key: str = ""
    virustotal_api_key: str = ""
    shodan_api_key: str = ""
    greynoise_api_key: str = ""
    timeout: float = 10.0

    @classmethod
    def from_environment(cls, env_file: str | Path = ".env") -> "Settings":
        load_dotenv(env_file)
        return cls(
            abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY", "").strip(),
            virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY", "").strip(),
            shodan_api_key=os.getenv("SHODAN_API_KEY", "").strip(),
            greynoise_api_key=os.getenv("GREYNOISE_API_KEY", "").strip(),
        )


