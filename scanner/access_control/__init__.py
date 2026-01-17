# scanner/access_control/__init__.py
from .idor import IDORScanner
from .path_traversal import PathTraversalScanner
from .forced_browsing import ForcedBrowsingScanner
from .jwt_vulnerabilities import JWTVulnerabilitiesScanner
from .privilege_escalation import PrivilegeEscalationScanner

__all__ = [
    'IDORScanner', 
    'PathTraversalScanner', 
    'ForcedBrowsingScanner', 
    'JWTVulnerabilitiesScanner',
    'PrivilegeEscalationScanner'
    ]