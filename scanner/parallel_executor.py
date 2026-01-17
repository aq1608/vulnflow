"""Parallel execution engine for vulnerability scanners"""

import asyncio
from typing import List, Dict, Any, Callable, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import time

from .base import Vulnerability


@dataclass
class ScanTask:
    """Represents a single scan task"""
    scanner_name: str
    scanner: Any
    url: str
    params: Dict[str, str] = None
    task_type: str = "param"  # "param" or "site"


@dataclass 
class ScanResult:
    """Result from a scan task"""
    scanner_name: str
    vulnerabilities: List[Vulnerability]
    duration: float
    error: Optional[str] = None


class ParallelScanExecutor:
    """
    Executes vulnerability scans in parallel with configurable concurrency.
    
    Features:
    - Concurrent scanner execution
    - Concurrent target scanning
    - Rate limiting to prevent overwhelming targets
    - Progress callbacks for UI updates
    """
    
    def __init__(
        self,
        max_concurrent_scanners: int = 5,
        max_concurrent_targets: int = 10,
        max_requests_per_second: float = 50.0,
        timeout_per_scan: float = 30.0
    ):
        """
        Initialize the parallel executor.
        
        Args:
            max_concurrent_scanners: Max scanners running simultaneously per target
            max_concurrent_targets: Max targets being scanned simultaneously
            max_requests_per_second: Rate limit for HTTP requests
            timeout_per_scan: Timeout for individual scan operations
        """
        self.max_concurrent_scanners = max_concurrent_scanners
        self.max_concurrent_targets = max_concurrent_targets
        self.max_requests_per_second = max_requests_per_second
        self.timeout_per_scan = timeout_per_scan
        
        # Semaphores for concurrency control
        self._scanner_semaphore = None
        self._target_semaphore = None
        self._rate_limiter = None
        
        # Statistics
        self.stats = {
            "total_tasks": 0,
            "completed_tasks": 0,
            "failed_tasks": 0,
            "total_duration": 0.0
        }
        
        # Progress callback
        self._progress_callback = None
        
        # Thread pool for CPU-bound operations
        self._thread_pool = ThreadPoolExecutor(max_workers=4)
    
    def set_progress_callback(self, callback: Callable[[int, int, str], None]):
        """Set a callback for progress updates: callback(completed, total, message)"""
        self._progress_callback = callback
    
    async def _init_semaphores(self):
        """Initialize semaphores (must be called within async context)"""
        self._scanner_semaphore = asyncio.Semaphore(self.max_concurrent_scanners)
        self._target_semaphore = asyncio.Semaphore(self.max_concurrent_targets)
        self._rate_limiter = RateLimiter(self.max_requests_per_second)
    
    async def execute_scan_task(
        self,
        session,
        task: ScanTask
    ) -> ScanResult:
        """Execute a single scan task with rate limiting"""
        start_time = time.time()
        
        try:
            # Acquire rate limiter
            await self._rate_limiter.acquire()
            
            # Execute the scan with timeout
            async with self._scanner_semaphore:
                if task.task_type == "site":
                    vulns = await asyncio.wait_for(
                        task.scanner.scan(session, task.url),
                        timeout=self.timeout_per_scan
                    )
                else:
                    vulns = await asyncio.wait_for(
                        task.scanner.scan(session, task.url, task.params or {}),
                        timeout=self.timeout_per_scan
                    )
                
                duration = time.time() - start_time
                return ScanResult(
                    scanner_name=task.scanner_name,
                    vulnerabilities=vulns,
                    duration=duration
                )
                
        except asyncio.TimeoutError:
            return ScanResult(
                scanner_name=task.scanner_name,
                vulnerabilities=[],
                duration=time.time() - start_time,
                error=f"Timeout after {self.timeout_per_scan}s"
            )
        except Exception as e:
            return ScanResult(
                scanner_name=task.scanner_name,
                vulnerabilities=[],
                duration=time.time() - start_time,
                error=str(e)
            )
    
    async def execute_target_scans(
        self,
        session,
        url: str,
        params: Dict[str, str],
        scanners: List[tuple]  # List of (name, scanner) tuples
    ) -> List[ScanResult]:
        """Execute all scanners against a single target in parallel"""
        async with self._target_semaphore:
            tasks = []
            for scanner_name, scanner in scanners:
                task = ScanTask(
                    scanner_name=scanner_name,
                    scanner=scanner,
                    url=url,
                    params=params,
                    task_type="param"
                )
                tasks.append(self.execute_scan_task(session, task))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Convert exceptions to ScanResults
            processed_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    processed_results.append(ScanResult(
                        scanner_name=scanners[i][0],
                        vulnerabilities=[],
                        duration=0,
                        error=str(result)
                    ))
                else:
                    processed_results.append(result)
            
            return processed_results
    
    async def execute_all_scans(
        self,
        session,
        targets: List[Dict],
        site_scanners: List[tuple],
        param_scanners: List[tuple],
        base_url: str
    ) -> List[Vulnerability]:
        """
        Execute all scans in parallel.
        
        Args:
            session: aiohttp ClientSession
            targets: List of target dicts with 'url' and 'params'
            site_scanners: List of (name, scanner) for site-wide scans
            param_scanners: List of (name, scanner) for parameter scans
            base_url: Base URL for site-wide scans
            
        Returns:
            List of all discovered vulnerabilities
        """
        await self._init_semaphores()
        
        all_vulnerabilities = []
        all_results = []
        
        # Calculate total tasks for progress
        total_tasks = len(site_scanners) + (len(targets) * len(param_scanners))
        self.stats["total_tasks"] = total_tasks
        completed = 0
        
        # Phase 1: Run site-wide scanners in parallel
        if site_scanners:
            site_tasks = []
            for scanner_name, scanner in site_scanners:
                task = ScanTask(
                    scanner_name=scanner_name,
                    scanner=scanner,
                    url=base_url,
                    task_type="site"
                )
                site_tasks.append(self.execute_scan_task(session, task))
            
            site_results = await asyncio.gather(*site_tasks, return_exceptions=True)
            
            for i, result in enumerate(site_results):
                if isinstance(result, ScanResult):
                    all_results.append(result)
                    all_vulnerabilities.extend(result.vulnerabilities)
                    if result.error:
                        self.stats["failed_tasks"] += 1
                completed += 1
                
                if self._progress_callback:
                    self._progress_callback(
                        completed, 
                        total_tasks,
                        f"Site scan: {site_scanners[i][0]}"
                    )
        
        # Phase 2: Run parameter scanners on all targets in parallel
        if targets and param_scanners:
            # Create batches to avoid overwhelming the system
            batch_size = self.max_concurrent_targets
            
            for batch_start in range(0, len(targets), batch_size):
                batch = targets[batch_start:batch_start + batch_size]
                
                # Execute all targets in batch concurrently
                batch_tasks = []
                for target in batch:
                    batch_tasks.append(
                        self.execute_target_scans(
                            session,
                            target['url'],
                            target['params'],
                            param_scanners
                        )
                    )
                
                batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
                
                for target_results in batch_results:
                    if isinstance(target_results, list):
                        for result in target_results:
                            all_results.append(result)
                            all_vulnerabilities.extend(result.vulnerabilities)
                            if result.error:
                                self.stats["failed_tasks"] += 1
                            completed += 1
                            
                            if self._progress_callback:
                                self._progress_callback(
                                    completed,
                                    total_tasks,
                                    f"Scanning: {result.scanner_name}"
                                )
        
        self.stats["completed_tasks"] = completed
        self.stats["total_duration"] = sum(r.duration for r in all_results if isinstance(r, ScanResult))
        
        return all_vulnerabilities
    
    def shutdown(self):
        """Shutdown the thread pool"""
        self._thread_pool.shutdown(wait=False)


class RateLimiter:
    """Token bucket rate limiter for controlling request rate"""
    
    def __init__(self, rate: float):
        """
        Initialize rate limiter.
        
        Args:
            rate: Maximum requests per second
        """
        self.rate = rate
        self.tokens = rate
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()
    
    async def acquire(self):
        """Acquire a token, waiting if necessary"""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
            self.last_update = now
            
            if self.tokens < 1:
                wait_time = (1 - self.tokens) / self.rate
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class ScanWorkerPool:
    """
    Worker pool for distributing scan tasks across multiple workers.
    Uses asyncio for I/O-bound operations and thread pool for CPU-bound.
    """
    
    def __init__(self, num_workers: int = 10):
        self.num_workers = num_workers
        self._queue = None
        self._workers = []
        self._results = []
        self._results_lock = asyncio.Lock()
    
    async def _worker(self, session, worker_id: int):
        """Worker coroutine that processes tasks from the queue"""
        while True:
            try:
                task = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            
            if task is None:  # Shutdown signal
                break
            
            try:
                scanner, url, params, task_type = task
                
                if task_type == "site":
                    vulns = await scanner.scan(session, url)
                else:
                    vulns = await scanner.scan(session, url, params)
                
                async with self._results_lock:
                    self._results.extend(vulns)
                    
            except Exception as e:
                pass  # Log error in production
            finally:
                self._queue.task_done()
    
    async def run(self, session, tasks: List[tuple]) -> List[Vulnerability]:
        """
        Run all tasks through the worker pool.
        
        Args:
            session: aiohttp session
            tasks: List of (scanner, url, params, task_type) tuples
            
        Returns:
            List of discovered vulnerabilities
        """
        self._queue = asyncio.Queue()
        self._results = []
        
        # Start workers
        self._workers = [
            asyncio.create_task(self._worker(session, i))
            for i in range(self.num_workers)
        ]
        
        # Add tasks to queue
        for task in tasks:
            await self._queue.put(task)
        
        # Wait for all tasks to complete
        await self._queue.join()
        
        # Send shutdown signal to workers
        for _ in self._workers:
            await self._queue.put(None)
        
        # Wait for workers to finish
        await asyncio.gather(*self._workers)
        
        return self._results