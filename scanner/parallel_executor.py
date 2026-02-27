# scanner/parallel_executor.py
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
    scanner:      Any
    url:          str
    params:       Dict[str, str] = None
    task_type:    str = "param"   # "param" or "site"


@dataclass
class ScanResult:
    """Result from a scan task"""
    scanner_name:    str
    vulnerabilities: List[Vulnerability]
    duration:        float
    error:           Optional[str] = None


class RateLimiter:
    """Token bucket rate limiter for controlling request rate"""

    def __init__(self, rate: float):
        self.rate        = rate
        self.tokens      = rate
        self.last_update = time.monotonic()
        # Defer lock creation until first use inside an async context
        self._lock: Optional[asyncio.Lock] = None

    async def acquire(self):
        """Acquire a token, waiting if necessary"""
        if self._lock is None:
            self._lock = asyncio.Lock()

        async with self._lock:
            now     = time.monotonic()
            elapsed = now - self.last_update
            self.tokens      = min(self.rate, self.tokens + elapsed * self.rate)
            self.last_update = now

            if self.tokens < 1:
                wait_time = (1 - self.tokens) / self.rate
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class ParallelScanExecutor:
    """
    Executes vulnerability scans in parallel with configurable concurrency.

    Features:
    - Site-wide scanners run ONCE against base_url (Phase 1)
    - Parameter scanners run per URL/param combination (Phase 2)
    - Configurable concurrency and rate limiting
    - Progress callbacks for UI updates
    - Full error visibility (no silent swallowing)
    """

    def __init__(
        self,
        max_concurrent_scanners: int   = 5,
        max_concurrent_targets:  int   = 10,
        max_requests_per_second: float = 50.0,
        timeout_per_scan:        float = 30.0,
    ):
        self.max_concurrent_scanners = max_concurrent_scanners
        self.max_concurrent_targets  = max_concurrent_targets
        self.max_requests_per_second = max_requests_per_second
        self.timeout_per_scan        = timeout_per_scan

        # Semaphores initialised lazily inside async context
        self._scanner_semaphore: Optional[asyncio.Semaphore] = None
        self._target_semaphore:  Optional[asyncio.Semaphore] = None
        self._rate_limiter:      Optional[RateLimiter]       = None

        self.stats = {
            "total_tasks":      0,
            "completed_tasks":  0,
            "failed_tasks":     0,
            "total_duration":   0.0,
        }

        self._progress_callback: Optional[Callable] = None
        self._thread_pool = ThreadPoolExecutor(max_workers=4)

    def set_progress_callback(self, callback: Callable[[int, int, str], None]):
        """Set callback: callback(completed, total, message)"""
        self._progress_callback = callback

    async def _init_semaphores(self):
        """Initialise semaphores inside the running event loop"""
        self._scanner_semaphore = asyncio.Semaphore(self.max_concurrent_scanners)
        self._target_semaphore  = asyncio.Semaphore(self.max_concurrent_targets)
        self._rate_limiter      = RateLimiter(self.max_requests_per_second)

    # ─────────────────────────────────────────────────────────────────────────
    # SINGLE TASK EXECUTION
    # ─────────────────────────────────────────────────────────────────────────

    async def execute_scan_task(
        self,
        session,
        task: ScanTask,
    ) -> ScanResult:
        """Execute one scan task with rate limiting and timeout"""
        start_time = time.time()

        try:
            await self._rate_limiter.acquire()

            async with self._scanner_semaphore:
                if task.task_type == "site":
                    vulns = await asyncio.wait_for(
                        task.scanner.scan(session, task.url),
                        timeout=self.timeout_per_scan,
                    )
                else:
                    vulns = await asyncio.wait_for(
                        task.scanner.scan(
                            session, task.url, task.params or {}
                        ),
                        timeout=self.timeout_per_scan,
                    )

            return ScanResult(
                scanner_name=task.scanner_name,
                vulnerabilities=vulns or [],
                duration=time.time() - start_time,
            )

        except asyncio.TimeoutError:
            return ScanResult(
                scanner_name=task.scanner_name,
                vulnerabilities=[],
                duration=time.time() - start_time,
                error=f"Timeout after {self.timeout_per_scan}s",
            )
        except Exception as e:
            return ScanResult(
                scanner_name=task.scanner_name,
                vulnerabilities=[],
                duration=time.time() - start_time,
                error=str(e),
            )

    # ─────────────────────────────────────────────────────────────────────────
    # PER-TARGET EXECUTION
    # ─────────────────────────────────────────────────────────────────────────

    async def execute_target_scans(
        self,
        session,
        url:      str,
        params:   Dict[str, str],
        scanners: List[tuple],
    ) -> List[ScanResult]:
        """Run all param scanners against one target concurrently"""
        async with self._target_semaphore:
            tasks = [
                self.execute_scan_task(
                    session,
                    ScanTask(
                        scanner_name=name,
                        scanner=scanner,
                        url=url,
                        params=params,
                        task_type="param",
                    ),
                )
                for name, scanner in scanners
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            processed: List[ScanResult] = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    processed.append(ScanResult(
                        scanner_name=scanners[i][0],
                        vulnerabilities=[],
                        duration=0.0,
                        error=str(result),
                    ))
                else:
                    processed.append(result)

            return processed

    # ─────────────────────────────────────────────────────────────────────────
    # MAIN ENTRY POINT
    # ─────────────────────────────────────────────────────────────────────────

    async def execute_all_scans(
        self,
        session,
        targets:        List[Dict],
        site_scanners:  List[tuple],
        param_scanners: List[tuple],
        base_url:       str,
    ) -> List[Vulnerability]:
        """
        Execute all scans in two phases:

        Phase 1 — Site scanners
            Each scanner called ONCE with base_url.
            Used for: headers, CORS, SSL, default_creds_misconfig,
                      default_creds_auth, backup files, etc.

        Phase 2 — Param scanners
            Each scanner called once per (url, param) target combination.
            Used for: SQLi, XSS, SSTI, IDOR, etc.
        """
        await self._init_semaphores()

        all_vulnerabilities: List[Vulnerability] = []
        all_results:         List[ScanResult]    = []

        total_tasks = (
            len(site_scanners)
            + len(targets) * len(param_scanners)
        )
        self.stats["total_tasks"] = total_tasks
        completed = 0

        # ── Phase 1: Site-wide scanners ───────────────────────────────────────
        if site_scanners:
            print(
                f"  [*] Phase 1: Running {len(site_scanners)} "
                f"site scanners against {base_url}"
            )

            site_tasks = [
                self.execute_scan_task(
                    session,
                    ScanTask(
                        scanner_name=name,
                        scanner=scanner,
                        url=base_url,
                        task_type="site",
                    ),
                )
                for name, scanner in site_scanners
            ]

            site_results = await asyncio.gather(
                *site_tasks, return_exceptions=True
            )

            for i, result in enumerate(site_results):
                scanner_name = site_scanners[i][0]

                if isinstance(result, Exception):
                    # Unhandled exception from gather — log and count
                    self.stats["failed_tasks"] += 1
                    print(
                        f"  [!] Site scanner '{scanner_name}' "
                        f"raised: {str(result)[:100]}"
                    )

                elif isinstance(result, ScanResult):
                    all_results.append(result)
                    all_vulnerabilities.extend(result.vulnerabilities)

                    if result.error:
                        self.stats["failed_tasks"] += 1
                        # Only print non-timeout errors to reduce noise
                        if "Timeout" not in result.error:
                            print(
                                f"  [!] Site scanner '{scanner_name}': "
                                f"{result.error[:100]}"
                            )
                    elif result.vulnerabilities:
                        print(
                            f"  [+] '{scanner_name}': "
                            f"{len(result.vulnerabilities)} finding(s)"
                        )

                completed += 1
                if self._progress_callback:
                    self._progress_callback(
                        completed, total_tasks,
                        f"Site scan: {scanner_name}",
                    )

        # ── Phase 2: Parameter scanners ───────────────────────────────────────
        if targets and param_scanners:
            print(
                f"  [*] Phase 2: Running {len(param_scanners)} param scanners "
                f"across {len(targets)} targets "
                f"(batch size: {self.max_concurrent_targets})"
            )

            batch_size = self.max_concurrent_targets

            for batch_start in range(0, len(targets), batch_size):
                batch = targets[batch_start : batch_start + batch_size]

                batch_tasks = [
                    self.execute_target_scans(
                        session,
                        target['url'],
                        target['params'],
                        param_scanners,
                    )
                    for target in batch
                ]

                batch_results = await asyncio.gather(
                    *batch_tasks, return_exceptions=True
                )

                for i, target_results in enumerate(batch_results):
                    if isinstance(target_results, Exception):
                        # Entire target failed — count all its scanner slots
                        self.stats["failed_tasks"] += len(param_scanners)
                        completed              += len(param_scanners)
                        target_url = batch[i].get('url', '?')
                        print(
                            f"  [!] Target scan failed "
                            f"({target_url[:60]}): "
                            f"{str(target_results)[:80]}"
                        )
                        if self._progress_callback:
                            self._progress_callback(
                                completed, total_tasks,
                                f"Target failed: {target_url[:40]}",
                            )

                    elif isinstance(target_results, list):
                        for result in target_results:
                            all_results.append(result)
                            all_vulnerabilities.extend(result.vulnerabilities)

                            if result.error:
                                self.stats["failed_tasks"] += 1

                            completed += 1
                            if self._progress_callback:
                                self._progress_callback(
                                    completed, total_tasks,
                                    f"Scanning: {result.scanner_name}",
                                )

        # ── Final stats ───────────────────────────────────────────────────────
        self.stats["completed_tasks"] = completed
        self.stats["total_duration"]  = sum(
            r.duration for r in all_results
            if isinstance(r, ScanResult)
        )

        print(
            f"  [*] Executor done — "
            f"{completed}/{total_tasks} tasks, "
            f"{self.stats['failed_tasks']} failed, "
            f"{len(all_vulnerabilities)} raw findings"
        )

        return all_vulnerabilities

    def shutdown(self):
        """Clean shutdown of thread pool"""
        self._thread_pool.shutdown(wait=False)