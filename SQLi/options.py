from dataclasses import dataclass
import os
from scan_safety import number


def techniques(value):
    value = value.strip().upper()
    if not value or any(letter not in 'BEUSTQ' for letter in value):
        raise ValueError('SQLI_TECHNIQUES: expected a nonempty subset of BEUSTQ')
    return ''.join(dict.fromkeys(value))


@dataclass(frozen=True)
class SQLiOptions:
    level: int
    risk: int
    techniques: str
    time_sec: int

    @classmethod
    def load(cls):
        return cls(number('SQLI_LEVEL', 3, 1, 5, int),
                   number('SQLI_RISK', 2, 1, 3, int),
                   techniques(os.environ.get('SQLI_TECHNIQUES', 'BEUSTQ')),
                   number('SQLI_TIME_SEC', 5, 1, 60, int))
