from .base import Scenario
from .d1_ci_scopes import D1
from .d2_onboarding import D2
from .s1_main import S1
from .s2_replay import S2
from .s3_hijack import S3
from .s4_fallback import S4

ALL: list[Scenario] = [S1(), S2(), S3(), S4(), D1(), D2()]

__all__ = ["ALL", "Scenario"]
