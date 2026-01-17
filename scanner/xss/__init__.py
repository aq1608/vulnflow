# scanner/xss/__init__.py
from .xss import XSSScanner
from .dom_xss import DOMXSSScanner

__all__ = ['XSSScanner', 'DOMXSSScanner']