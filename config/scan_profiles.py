"""
VulnFlow Enhanced - Configuration Templates

This file contains pre-configured scan profiles for different use cases.

## How to Use

Copy the relevant configuration and customize for your needs:

```python
from scanner.enhanced_vuln_scanner import EnhancedVulnerabilityScanner
from config.scan_profiles import PRODUCTION_SITE_CONFIG

# Use a pre-configured profile
scanner = EnhancedVulnerabilityScanner(PRODUCTION_SITE_CONFIG)
```

## Available Profiles

### By Environment:
- PRODUCTION_SITE_CONFIG - For live client sites
- STAGING_SITE_CONFIG - For staging environments
- DEV_SITE_CONFIG - For development

### By Scan Type:
- QUICK_SCAN_CONFIG - 5-10 minute scans
- STANDARD_SCAN_CONFIG - 20-40 minute scans
- COMPREHENSIVE_SCAN_CONFIG - 60+ minute scans

### By Technology:
- PHP_APPLICATION_CONFIG - PHP/MySQL applications
- NODEJS_APPLICATION_CONFIG - Node.js applications
- PYTHON_APPLICATION_CONFIG - Django/Flask applications
- JAVA_APPLICATION_CONFIG - Spring Boot/Java applications

### By Use Case:
- API_SCAN_CONFIG - REST/GraphQL APIs
- PCI_DSS_SCAN_CONFIG - PCI DSS compliance
- CI_CD_SCAN_CONFIG - Pipeline integration
- WEEKLY_SCAN_CONFIG - Scheduled monitoring

### Custom Builder:
- build_custom_config() - Build custom configurations
"""

# ==============================================================================
# PRODUCTION CONFIGURATIONS
# ==============================================================================

# For scanning client production websites (very conservative)
PRODUCTION_SITE_CONFIG = {
    'mode': 'owasp',                      # Full OWASP Top 10 coverage
    'smart_payloads': True,               # AI-generated payloads
    'confidence_threshold': 0.75,         # High confidence only
    'max_concurrent_scanners': 3,         # Gentle on server
    'max_concurrent_targets': 6,
    'requests_per_second': 25,            # Very respectful rate
    'timeout': 35,
    'enabled_scanners': None,             # All scanners
    'disabled_scanners': [],
}

# For staging/UAT environments (balanced)
STAGING_SITE_CONFIG = {
    'mode': 'owasp',
    'smart_payloads': True,
    'confidence_threshold': 0.65,
    'max_concurrent_scanners': 6,
    'max_concurrent_targets': 12,
    'requests_per_second': 60,
    'timeout': 25,
}

# For development/test environments (faster)
DEV_SITE_CONFIG = {
    'mode': 'standard',
    'smart_payloads': True,
    'confidence_threshold': 0.6,
    'max_concurrent_scanners': 8,
    'max_concurrent_targets': 15,
    'requests_per_second': 75,
    'timeout': 20,
}

# ==============================================================================
# SCAN TYPE CONFIGURATIONS
# ==============================================================================

# Quick initial assessment (5-10 minutes)
QUICK_SCAN_CONFIG = {
    'mode': 'quick',
    'smart_payloads': True,
    'confidence_threshold': 0.6,
    'max_concurrent_scanners': 10,
    'max_concurrent_targets': 20,
    'requests_per_second': 100,
    'timeout': 15,
}

# Standard OWASP scan (20-40 minutes)
STANDARD_SCAN_CONFIG = {
    'mode': 'standard',
    'smart_payloads': True,
    'confidence_threshold': 0.65,
    'max_concurrent_scanners': 6,
    'max_concurrent_targets': 12,
    'requests_per_second': 60,
    'timeout': 25,
}

# Comprehensive deep scan (60+ minutes)
COMPREHENSIVE_SCAN_CONFIG = {
    'mode': 'owasp',
    'smart_payloads': True,
    'confidence_threshold': 0.7,
    'max_concurrent_scanners': 5,
    'max_concurrent_targets': 10,
    'requests_per_second': 50,
    'timeout': 30,
}

# ==============================================================================
# TECHNOLOGY-SPECIFIC CONFIGURATIONS
# ==============================================================================

# For PHP/MySQL applications (e.g., WordPress, Drupal, custom PHP)
PHP_APPLICATION_CONFIG = {
    'mode': 'owasp',
    'smart_payloads': True,
    'confidence_threshold': 0.7,
    'max_concurrent_scanners': 6,
    'max_concurrent_targets': 12,
    'requests_per_second': 50,
    'timeout': 25,
    # Focus on common PHP vulnerabilities
    'enabled_scanners': [
        'sqli', 'xss', 'cmdi', 'ssti', 'xxe',
        'path_traversal', 'idor', 'headers', 'cors',
        'ssl_tls', 'backup', 'debug'
    ]
}

# For Node.js/JavaScript applications (SPAs, REST APIs)
NODEJS_APPLICATION_CONFIG = {
    'mode': 'owasp',
    'smart_payloads': True,
    'confidence_threshold': 0.7,
    'max_concurrent_scanners': 6,
    'max_concurrent_targets': 12,
    'requests_per_second': 60,
    'timeout': 25,
    # Focus on API and JavaScript vulnerabilities
    'enabled_scanners': [
        'nosqli', 'xss', 'ssrf', 'jwt', 'headers',
        'cors', 'rate_limiting', 'mass_assignment',
        'deserialization', 'graphql'
    ]
}

# For Python applications (Django, Flask)
PYTHON_APPLICATION_CONFIG = {
    'mode': 'owasp',
    'smart_payloads': True,
    'confidence_threshold': 0.7,
    'max_concurrent_scanners': 6,
    'max_concurrent_targets': 12,
    'requests_per_second': 50,
    'timeout': 25,
    'enabled_scanners': [
        'sqli', 'nosqli', 'xss', 'ssti', 'xxe',
        'idor', 'path_traversal', 'headers', 'cors',
        'ssl_tls', 'deserialization'
    ]
}

# For Java applications (Spring Boot, JSP)
JAVA_APPLICATION_CONFIG = {
    'mode': 'owasp',
    'smart_payloads': True,
    'confidence_threshold': 0.7,
    'max_concurrent_scanners': 5,
    'max_concurrent_targets': 10,
    'requests_per_second': 40,
    'timeout': 30,
    'enabled_scanners': [
        'sqli', 'xss', 'xxe', 'deserialization',
        'idor', 'path_traversal', 'headers', 'cors',
        'ssl_tls', 'debug'
    ]
}

# ==============================================================================
# SPECIALIZED SCAN CONFIGURATIONS
# ==============================================================================

# API-focused scan (REST, GraphQL)
API_SCAN_CONFIG = {
    'mode': 'standard',
    'smart_payloads': True,
    'confidence_threshold': 0.65,
    'max_concurrent_scanners': 8,
    'max_concurrent_targets': 15,
    'requests_per_second': 75,
    'timeout': 20,
    'enabled_scanners': [
        'sqli', 'nosqli', 'cmdi', 'ssrf', 'xxe',
        'idor', 'jwt', 'rate_limiting', 'cors',
        'mass_assignment', 'graphql', 'headers',
        'deserialization'
    ]
}

# Injection-focused scan
INJECTION_SCAN_CONFIG = {
    'mode': 'standard',
    'smart_payloads': True,
    'confidence_threshold': 0.65,
    'max_concurrent_scanners': 8,
    'max_concurrent_targets': 15,
    'requests_per_second': 60,
    'timeout': 25,
    'enabled_scanners': [
        'sqli', 'nosqli', 'cmdi', 'ssti', 'xxe',
        'ldapi', 'xpath'
    ]
}

# Authentication/Authorization focused
AUTH_SCAN_CONFIG = {
    'mode': 'standard',
    'smart_payloads': True,
    'confidence_threshold': 0.7,
    'max_concurrent_scanners': 6,
    'max_concurrent_targets': 12,
    'requests_per_second': 50,
    'timeout': 25,
    'enabled_scanners': [
        'idor', 'jwt', 'session_fixation', 'privilege_escalation',
        'forced_browsing', 'weak_password'
    ]
}

# ==============================================================================
# COMPLIANCE CONFIGURATIONS
# ==============================================================================

# PCI DSS 6.6 compliant scan
PCI_DSS_SCAN_CONFIG = {
    'mode': 'owasp',
    'smart_payloads': True,
    'confidence_threshold': 0.75,  # High accuracy for compliance
    'max_concurrent_scanners': 5,
    'max_concurrent_targets': 10,
    'requests_per_second': 40,
    'timeout': 30,
}

# OWASP Top 10 focused (for compliance reporting)
OWASP_COMPLIANCE_CONFIG = {
    'mode': 'owasp',
    'smart_payloads': True,
    'confidence_threshold': 0.7,
    'max_concurrent_scanners': 6,
    'max_concurrent_targets': 12,
    'requests_per_second': 50,
    'timeout': 25,
}

# ==============================================================================
# PERFORMANCE TUNING CONFIGURATIONS
# ==============================================================================

# Maximum speed (for testing/research only)
MAXIMUM_SPEED_CONFIG = {
    'mode': 'quick',
    'smart_payloads': False,  # Faster without AI
    'confidence_threshold': 0.5,
    'max_concurrent_scanners': 15,
    'max_concurrent_targets': 25,
    'requests_per_second': 150,
    'timeout': 10,
}

# Maximum accuracy (slower but very thorough)
MAXIMUM_ACCURACY_CONFIG = {
    'mode': 'full',
    'smart_payloads': True,
    'confidence_threshold': 0.8,
    'max_concurrent_scanners': 3,
    'max_concurrent_targets': 5,
    'requests_per_second': 20,
    'timeout': 40,
}

# Balanced (recommended default)
BALANCED_CONFIG = {
    'mode': 'standard',
    'smart_payloads': True,
    'confidence_threshold': 0.65,
    'max_concurrent_scanners': 6,
    'max_concurrent_targets': 12,
    'requests_per_second': 60,
    'timeout': 25,
}

# ==============================================================================
# CI/CD CONFIGURATIONS
# ==============================================================================

# For CI/CD pipelines (fast, focused on criticals)
CI_CD_SCAN_CONFIG = {
    'mode': 'quick',
    'smart_payloads': True,
    'confidence_threshold': 0.7,
    'max_concurrent_scanners': 10,
    'max_concurrent_targets': 20,
    'requests_per_second': 100,
    'timeout': 15,
}

# For scheduled weekly scans
WEEKLY_SCAN_CONFIG = {
    'mode': 'owasp',
    'smart_payloads': True,
    'confidence_threshold': 0.7,
    'max_concurrent_scanners': 6,
    'max_concurrent_targets': 12,
    'requests_per_second': 50,
    'timeout': 25,
}

# ==============================================================================
# CUSTOM CONFIGURATION BUILDER
# ==============================================================================

def build_custom_config(
    environment='production',  # 'production', 'staging', 'dev'
    speed='balanced',          # 'fast', 'balanced', 'thorough'
    coverage='standard'        # 'quick', 'standard', 'owasp', 'full'
):
    """
    Build a custom configuration based on requirements.
    
    Args:
        environment: Target environment type
            - 'production': Conservative settings for live sites
            - 'staging': Balanced settings for staging
            - 'dev': Faster settings for development
        
        speed: Scan speed preference
            - 'fast': Quick scans, higher concurrency
            - 'balanced': Good balance of speed and accuracy
            - 'thorough': Slower, more comprehensive
        
        coverage: Vulnerability coverage level
            - 'quick': Quick assessment (5-10 min)
            - 'standard': Standard OWASP coverage (20-40 min)
            - 'owasp': Full OWASP Top 10 (40-90 min)
            - 'full': Everything available (60+ min)
    
    Returns:
        Configuration dictionary
    
    Examples:
        >>> config = build_custom_config('staging', 'balanced', 'owasp')
        >>> scanner = EnhancedVulnerabilityScanner(config)
        
        >>> config = build_custom_config('production', 'thorough', 'owasp')
        >>> scanner = EnhancedVulnerabilityScanner(config)
    """
    
    # Base configuration
    config = {
        'mode': coverage,
        'smart_payloads': True,
    }
    
    # Environment-specific settings
    env_settings = {
        'production': {
            'confidence_threshold': 0.75,
            'max_concurrent_scanners': 3,
            'max_concurrent_targets': 6,
            'requests_per_second': 25,
            'timeout': 35,
        },
        'staging': {
            'confidence_threshold': 0.65,
            'max_concurrent_scanners': 6,
            'max_concurrent_targets': 12,
            'requests_per_second': 60,
            'timeout': 25,
        },
        'dev': {
            'confidence_threshold': 0.6,
            'max_concurrent_scanners': 8,
            'max_concurrent_targets': 15,
            'requests_per_second': 75,
            'timeout': 20,
        }
    }
    
    # Speed adjustments
    speed_multipliers = {
        'fast': {'workers': 1.5, 'targets': 1.5, 'rate': 1.5, 'timeout': 0.7},
        'balanced': {'workers': 1.0, 'targets': 1.0, 'rate': 1.0, 'timeout': 1.0},
        'thorough': {'workers': 0.7, 'targets': 0.7, 'rate': 0.7, 'timeout': 1.3},
    }
    
    # Apply settings
    base = env_settings.get(environment, env_settings['staging'])
    multiplier = speed_multipliers.get(speed, speed_multipliers['balanced'])
    
    config.update({
        'confidence_threshold': base['confidence_threshold'],
        'max_concurrent_scanners': int(base['max_concurrent_scanners'] * multiplier['workers']),
        'max_concurrent_targets': int(base['max_concurrent_targets'] * multiplier['targets']),
        'requests_per_second': int(base['requests_per_second'] * multiplier['rate']),
        'timeout': int(base['timeout'] * multiplier['timeout']),
    })
    
    return config


# ==============================================================================
# USAGE EXAMPLES
# ==============================================================================

if __name__ == '__main__':
    print("VulnFlow Enhanced - Configuration Templates\n")
    print("=" * 70)
    print("Available Pre-Configured Profiles:")
    print("=" * 70)
    
    profiles = [
        ("PRODUCTION_SITE_CONFIG", "Conservative for live sites"),
        ("STAGING_SITE_CONFIG", "Balanced for staging"),
        ("DEV_SITE_CONFIG", "Faster for development"),
        ("QUICK_SCAN_CONFIG", "Quick assessment (5-10 min)"),
        ("STANDARD_SCAN_CONFIG", "Standard scan (20-40 min)"),
        ("COMPREHENSIVE_SCAN_CONFIG", "Deep scan (60+ min)"),
        ("PHP_APPLICATION_CONFIG", "Optimized for PHP/MySQL"),
        ("NODEJS_APPLICATION_CONFIG", "Optimized for Node.js"),
        ("PYTHON_APPLICATION_CONFIG", "Optimized for Python"),
        ("JAVA_APPLICATION_CONFIG", "Optimized for Java"),
        ("API_SCAN_CONFIG", "REST/GraphQL APIs"),
        ("PCI_DSS_SCAN_CONFIG", "PCI DSS compliance"),
        ("CI_CD_SCAN_CONFIG", "CI/CD pipelines"),
        ("WEEKLY_SCAN_CONFIG", "Scheduled monitoring"),
    ]
    
    for name, desc in profiles:
        print(f"  • {name:30} - {desc}")
    
    print("\n" + "=" * 70)
    print("Custom Configuration Builder:")
    print("=" * 70)
    print("\nExample 1: Production site, thorough scan")
    config1 = build_custom_config('production', 'thorough', 'owasp')
    print(f"  Confidence: {config1['confidence_threshold']}")
    print(f"  Workers: {config1['max_concurrent_scanners']}")
    print(f"  Rate: {config1['requests_per_second']} req/s")
    
    print("\nExample 2: Staging environment, balanced scan")
    config2 = build_custom_config('staging', 'balanced', 'standard')
    print(f"  Confidence: {config2['confidence_threshold']}")
    print(f"  Workers: {config2['max_concurrent_scanners']}")
    print(f"  Rate: {config2['requests_per_second']} req/s")
    
    print("\nExample 3: Dev environment, fast scan")
    config3 = build_custom_config('dev', 'fast', 'quick')
    print(f"  Confidence: {config3['confidence_threshold']}")
    print(f"  Workers: {config3['max_concurrent_scanners']}")
    print(f"  Rate: {config3['requests_per_second']} req/s")
    
    print("\n" + "=" * 70)
    print("Usage:")
    print("=" * 70)
    print("""
from config.scan_profiles import PRODUCTION_SITE_CONFIG
from scanner.enhanced_vuln_scanner import EnhancedVulnerabilityScanner

# Use a pre-configured profile
scanner = EnhancedVulnerabilityScanner(PRODUCTION_SITE_CONFIG)

# Or build a custom configuration
from config.scan_profiles import build_custom_config
config = build_custom_config('staging', 'balanced', 'owasp')
scanner = EnhancedVulnerabilityScanner(config)
""")
    print("=" * 70)