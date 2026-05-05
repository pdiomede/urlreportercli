from __future__ import annotations

from .base import Finding, ScanResult, Scanner, SEVERITY_ORDER
from .caa import CAAScanner
from .crtsh import CrtShScanner
from .dnssec import DNSSECScanner
from .dos_posture import DoSPostureScanner
from .email_auth import EmailAuthScanner
from .hsts_preload import HSTSPreloadScanner
from .https_redirect import HTTPSRedirectScanner
from .internetnl import InternetNLScanner
from .mozilla_observatory import MozillaObservatoryScanner
from .security_headers import SecurityHeadersScanner
from .security_txt import SecurityTxtScanner
from .ssllabs import SSLLabsScanner

REGISTRY: dict[str, type] = {
    "ssl_labs": SSLLabsScanner,
    "mozilla_observatory": MozillaObservatoryScanner,
    "security_headers": SecurityHeadersScanner,
    "internetnl": InternetNLScanner,
    "hsts_preload": HSTSPreloadScanner,
    "crtsh": CrtShScanner,
    "caa": CAAScanner,
    "dnssec": DNSSECScanner,
    "https_redirect": HTTPSRedirectScanner,
    "dos_posture": DoSPostureScanner,
    "email_auth": EmailAuthScanner,
    "security_txt": SecurityTxtScanner,
}

__all__ = [
    "Finding",
    "ScanResult",
    "Scanner",
    "SEVERITY_ORDER",
    "REGISTRY",
    "SSLLabsScanner",
    "MozillaObservatoryScanner",
    "SecurityHeadersScanner",
    "InternetNLScanner",
    "HSTSPreloadScanner",
    "CrtShScanner",
    "CAAScanner",
    "DNSSECScanner",
    "HTTPSRedirectScanner",
    "DoSPostureScanner",
    "EmailAuthScanner",
    "SecurityTxtScanner",
]
