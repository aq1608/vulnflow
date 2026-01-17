# scanner/fast_scanner.py

from typing import Dict, List, Optional, Any
from scanner.parallel_executor import ParallelAnalyzer, ScanConfig, ScanMode
from crawler.spider import Spider
from detector.tech_fingerprint import TechFingerprint
import asyncio
import logging

logger = logging.getLogger(__name__)


class FastScanner:
    """
    High-level scanner interface with concurrency support
    """
    
    def __init__(
        self,
        target_url: str,
        mode: str = "full",
        workers: int = 10,
        **kwargs
    ):
        self.target_url = target_url
        
        # Build configuration preserving all parameters
        self.config = ScanConfig(
            target_url=target_url,
            max_workers=workers,
            scan_mode=ScanMode(mode),
            timeout=kwargs.get("timeout", 30),
            rate_limit=kwargs.get("rate_limit", 0.1),
            max_depth=kwargs.get("max_depth", 3),
            cookies=kwargs.get("cookies", {}),
            headers=kwargs.get("headers", {}),
            auth_token=kwargs.get("auth_token"),
            proxy=kwargs.get("proxy"),
            injection_depth=kwargs.get("injection_depth", "thorough"),
            xss_contexts=kwargs.get("xss_contexts", ["html", "attr", "js", "url"]),
            check_blind_vulns=kwargs.get("check_blind", True),
            callback_url=kwargs.get("callback_url"),
            custom_payloads=kwargs.get("custom_payloads", {}),
            enabled_modules=kwargs.get("modules", [])
        )
        
        self.spider = Spider(
            target_url=target_url,
            max_depth=self.config.max_depth,
            headers=self.config.headers,
            cookies=self.config.cookies
        )
        
        self.fingerprinter = TechFingerprint()
        self.analyzer = ParallelAnalyzer(self.config)
        
    def run(self, progress_callback=None) -> Dict[str, Any]:
        """
        Execute full scan pipeline with parallelization
        """
        logger.info(f"Starting fast scan on {self.target_url}")
        
        # 1. Technology fingerprinting
        logger.info("Phase 1: Technology fingerprinting...")
        tech_stack = self.fingerprinter.detect(self.target_url)
        
        # 2. Crawling/Spidering
        logger.info("Phase 2: Crawling target...")
        endpoints = self.spider.crawl()
        logger.info(f"Discovered {len(endpoints)} endpoints")
        
        # 3. Set progress callback if provided
        if progress_callback:
            self.analyzer.set_progress_callback(progress_callback)
        
        # 4. Parallel vulnerability scanning
        logger.info("Phase 3: Parallel vulnerability analysis...")
        results = self.analyzer.scan_parallel(endpoints)
        
        # 5. Add tech stack info to results
        results["technology_stack"] = tech_stack
        
        return results
    
    async def run_async(self, progress_callback=None) -> Dict[str, Any]:
        """
        Fully async scan pipeline for maximum performance
        """
        logger.info(f"Starting async fast scan on {self.target_url}")
        
        # Fingerprinting and crawling can run in parallel
        tech_task = asyncio.create_task(
            asyncio.to_thread(self.fingerprinter.detect, self.target_url)
        )
        crawl_task = asyncio.create_task(
            asyncio.to_thread(self.spider.crawl)
        )
        
        tech_stack, endpoints = await asyncio.gather(tech_task, crawl_task)
        
        logger.info(f"Discovered {len(endpoints)} endpoints")
        
        if progress_callback:
            self.analyzer.set_progress_callback(progress_callback)
        
        # Async vulnerability scanning
        results = await self.analyzer.scan_async(endpoints)
        results["technology_stack"] = tech_stack
        
        return results
    
    def stop(self):
        """Stop the scan gracefully"""
        self.analyzer.stop()