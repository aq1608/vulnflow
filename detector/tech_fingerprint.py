# websec/detector/tech_fingerprint.py
import re
from typing import Dict, List
from dataclasses import dataclass, field


@dataclass
class TechSignature:
    name: str
    category: str
    patterns: Dict[str, List[str]] = field(default_factory=dict)
    confidence_weight: float = 1.0


class TechnologyDetector:
    """Detect web technologies from HTTP responses"""
    
    def __init__(self):
        self.signatures = self._load_signatures()
    
    def _load_signatures(self) -> List[TechSignature]:
        """Load technology detection signatures"""
        return [
            TechSignature(
                name="Django",
                category="framework",
                patterns={
                    "headers": [r"csrftoken", r"django"],
                    "cookies": [r"csrftoken", r"sessionid"],
                    "body": [r"csrfmiddlewaretoken", r"__admin_media_prefix__"],
                },
                confidence_weight=1.0
            ),
            TechSignature(
                name="Flask",
                category="framework",
                patterns={
                    "headers": [r"Werkzeug"],
                    "cookies": [r"session="],
                },
                confidence_weight=0.8
            ),
            TechSignature(
                name="Express.js",
                category="framework",
                patterns={
                    "headers": [r"X-Powered-By:\s*Express"],
                    "cookies": [r"connect\.sid"],
                },
                confidence_weight=0.9
            ),
            TechSignature(
                name="React",
                category="frontend",
                patterns={
                    "body": [r"_reactRoot", r"__REACT", r"react-root", r"data-reactroot"],
                },
                confidence_weight=0.85
            ),
            TechSignature(
                name="Vue.js",
                category="frontend",
                patterns={
                    "body": [r"v-cloak", r"v-if", r"v-for", r"__vue__"],
                },
                confidence_weight=0.85
            ),
            TechSignature(
                name="Angular",
                category="frontend",
                patterns={
                    "body": [r"ng-version", r"ng-app", r"ng-controller", r"ngModel"],
                },
                confidence_weight=0.85
            ),
            TechSignature(
                name="WordPress",
                category="cms",
                patterns={
                    "body": [r"wp-content", r"wp-includes", r"wp-json"],
                    "headers": [r"X-Powered-By.*PHP"],
                },
                confidence_weight=1.0
            ),
            TechSignature(
                name="Laravel",
                category="framework",
                patterns={
                    "cookies": [r"laravel_session", r"XSRF-TOKEN"],
                    "body": [r"laravel", r"csrf-token"],
                },
                confidence_weight=0.95
            ),
            TechSignature(
                name="Spring Boot",
                category="framework",
                patterns={
                    "headers": [r"X-Application-Context"],
                    "body": [r"Whitelabel Error Page"],
                    "cookies": [r"JSESSIONID"],
                },
                confidence_weight=0.9
            ),
            TechSignature(
                name="ASP.NET",
                category="framework",
                patterns={
                    "headers": [r"X-AspNet-Version", r"X-Powered-By.*ASP\.NET"],
                    "cookies": [r"ASP\.NET_SessionId", r"__RequestVerificationToken"],
                    "body": [r"__VIEWSTATE", r"__EVENTVALIDATION"],
                },
                confidence_weight=1.0
            ),
            TechSignature(
                name="PHP",
                category="language",
                patterns={
                    "headers": [r"X-Powered-By.*PHP"],
                    "cookies": [r"PHPSESSID"],
                },
                confidence_weight=0.9
            ),
            TechSignature(
                name="Nginx",
                category="server",
                patterns={
                    "headers": [r"Server:\s*nginx"],
                },
                confidence_weight=1.0
            ),
            TechSignature(
                name="Apache",
                category="server",
                patterns={
                    "headers": [r"Server:\s*Apache"],
                },
                confidence_weight=1.0
            ),
            TechSignature(
                name="jQuery",
                category="library",
                patterns={
                    "body": [r"jquery", r"jQuery"],
                },
                confidence_weight=0.7
            ),
            TechSignature(
                name="Bootstrap",
                category="library",
                patterns={
                    "body": [r"bootstrap\.min\.(js|css)", r"class=\".*btn btn-"],
                },
                confidence_weight=0.7
            ),
        ]
    
    def detect(self, response_data: Dict) -> Dict[str, Dict]:
        """Detect technologies from response data"""
        detected = {}
        
        for sig in self.signatures:
            confidence = self._calculate_confidence(sig, response_data)
            if confidence > 0.3:
                detected[sig.name] = {
                    "confidence": confidence,
                    "category": sig.category
                }
        
        return detected
    
    def _calculate_confidence(self, sig: TechSignature, 
                              response_data: Dict) -> float:
        """Calculate detection confidence score"""
        matches = 0
        total_patterns = 0
        
        for location, patterns in sig.patterns.items():
            content = response_data.get(location, "")
            if isinstance(content, dict):
                content = str(content)
            
            for pattern in patterns:
                total_patterns += 1
                if re.search(pattern, content, re.IGNORECASE):
                    matches += 1
        
        if total_patterns == 0:
            return 0
        
        return (matches / total_patterns) * sig.confidence_weight
    
    def detect_from_crawl_results(self, crawl_results: Dict) -> Dict[str, Dict]:
        """Detect technologies from crawl results"""
        all_detected = {}
        
        for url, data in crawl_results.get("urls", {}).items():
            if isinstance(data, dict) and "error" not in data:
                detected = self.detect(data)
                for tech, info in detected.items():
                    if tech not in all_detected:
                        all_detected[tech] = info
                    else:
                        # Keep highest confidence
                        if info["confidence"] > all_detected[tech]["confidence"]:
                            all_detected[tech] = info
        
        return all_detected