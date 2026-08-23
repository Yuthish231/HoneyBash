from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger("honeybash.error")


def set_local_vars(self, config: str | None = None):
    if not config:
        return
    try:
        config_data = json.loads(Path(config).read_text())
        honeypots = config_data.get("honeypots", [])
        honeypot = self.__class__.__name__[1:-6].lower()
        if honeypot and honeypot in honeypots:
            for attr, value in honeypots[honeypot].items():
                setattr(self, attr, value)
                if attr == "port":
                    self.auto_disabled = True
    except Exception as error:
        logger.debug(f"Setting local variables failed: {error}", exc_info=True)


def load_config_file(config_path: str | Path) -> dict:
    path = Path(config_path)
    if not path.is_file():
        raise FileNotFoundError(f"Config file '{path}' not found")
    data = json.loads(path.read_text())
    return data
