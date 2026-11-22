"""
Настройки покрытия sqlmap; задержка задаётся отдельно от уровня проверок.
"""

from dataclasses import dataclass
from typing import Optional

from .waf_detect import WafDetectionResult


@dataclass
class ScanProfile:
    level: int
    risk: int
    tamper: Optional[str]
    delay: float
    random_agent: bool = True


def build_profile(
    waf: WafDetectionResult,
    *,
    max_level: int = 5,
    max_risk: int = 3,
    is_trusted_target: bool = False,
) -> ScanProfile:
    # Load limits at invocation time, after the bot has loaded its .env.
    from scan_safety import Limits
    from .options import SQLiOptions
    options = SQLiOptions.load()
    return ScanProfile(level=min(options.level, max_level), risk=min(options.risk, max_risk), tamper=None,
                       delay=Limits.load().interval, random_agent=False)
