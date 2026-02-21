# crawler/__init__.py
from .spider import AsyncWebCrawler, AuthConfig

try:
    from .spa_spider import SPAWebCrawler
    SPA_CRAWLER_AVAILABLE = True
except ImportError:
    SPA_CRAWLER_AVAILABLE = False

__all__ = ['AsyncWebCrawler', 'AuthConfig', 'SPAWebCrawler', 'SPA_CRAWLER_AVAILABLE']