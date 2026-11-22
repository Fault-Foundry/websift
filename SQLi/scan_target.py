from dataclasses import dataclass


@dataclass
class ScanTarget:
    url: str
    method: str = "GET"
    params: dict | None = None
    data: dict | None = None
    cookies: dict | None = None
