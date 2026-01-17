"""Advanced scan task scheduler with priority and load balancing"""

import asyncio
import time
from typing import List, Dict, Any, Optional, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import heapq

from .base import Vulnerability


class TaskPriority(Enum):
    """Task priority levels"""
    CRITICAL = 1  # Critical vulnerability scanners (SQLi, RCE)
    HIGH = 2      # High-impact scanners (XSS, SSRF)
    NORMAL = 3    # Standard scanners
    LOW = 4       # Info/recon scanners
    BACKGROUND = 5  # Low priority background tasks


@dataclass(order=True)
class ScanTask:
    """Represents a scheduled scan task"""
    priority: int
    created_at: float = field(compare=False)
    scanner_name: str = field(compare=False)
    scanner: Any = field(compare=False)
    url: str = field(compare=False)
    params: Dict[str, str] = field(compare=False, default_factory=dict)
    task_type: str = field(compare=False, default="param")
    retries: int = field(compare=False, default=0)
    max_retries: int = field(compare=False, default=2)
    host: str = field(compare=False, default="")
    
    def __post_init__(self):
        if not self.host and self.url:
            from urllib.parse import urlparse
            parsed = urlparse(self.url)
            self.host = parsed.netloc


@dataclass
class TaskResult:
    """Result from a completed task"""
    task: ScanTask
    vulnerabilities: List[Vulnerability]
    duration: float
    success: bool
    error: Optional[str] = None


class ScanScheduler:
    """
    Advanced task scheduler with:
    - Priority-based execution
    - Per-host load balancing
    - Automatic retry with backoff
    - Task deduplication
    - Progress tracking
    """
    
    def __init__(
        self,
        max_concurrent_tasks: int = 20,
        max_per_host: int = 5,
        retry_delay: float = 2.0,
        task_timeout: float = 30.0
    ):
        self.max_concurrent_tasks = max_concurrent_tasks
        self.max_per_host = max_per_host
        self.retry_delay = retry_delay
        self.task_timeout = task_timeout
        
        # Task queue (priority heap)
        self._task_queue: List[ScanTask] = []
        
        # Tracking
        self._pending_tasks: Set[str] = set()
        self._running_tasks: Dict[str, ScanTask] = {}
        self._completed_count = 0
        self._failed_count = 0
        
        # Per-host tracking
        self._host_running: Dict[str, int] = defaultdict(int)
        
        # Concurrency control
        self._global_semaphore: Optional[asyncio.Semaphore] = None
        self._host_semaphores: Dict[str, asyncio.Semaphore] = {}
        
        # Results
        self._results: List[TaskResult] = []
        self._all_vulnerabilities: List[Vulnerability] = []
        
        # Callbacks
        self._progress_callback: Optional[Callable] = None
        self._task_complete_callback: Optional[Callable] = None
        
        # State
        self._running = False
        self._lock = asyncio.Lock()
    
    def set_progress_callback(self, callback: Callable[[int, int, str], None]):
        """Set progress callback: callback(completed, total, message)"""
        self._progress_callback = callback
    
    def set_task_complete_callback(self, callback: Callable[[TaskResult], None]):
        """Set callback for task completion"""
        self._task_complete_callback = callback
    
    def _get_task_key(self, task: ScanTask) -> str:
        """Generate unique key for task deduplication"""
        params_key = tuple(sorted(task.params.items())) if task.params else ()
        return f"{task.scanner_name}:{task.url}:{params_key}:{task.task_type}"
    
    async def add_task(
        self,
        scanner_name: str,
        scanner: Any,
        url: str,
        params: Dict[str, str] = None,
        task_type: str = "param",
        priority: TaskPriority = TaskPriority.NORMAL
    ) -> bool:
        """
        Add a task to the scheduler.
        
        Returns:
            True if task was added, False if duplicate
        """
        task = ScanTask(
            priority=priority.value,
            created_at=time.time(),
            scanner_name=scanner_name,
            scanner=scanner,
            url=url,
            params=params or {},
            task_type=task_type
        )
        
        task_key = self._get_task_key(task)
        
        async with self._lock:
            if task_key in self._pending_tasks:
                return False
            
            self._pending_tasks.add(task_key)
            heapq.heappush(self._task_queue, task)
            return True
    
    async def add_tasks_batch(
        self,
        tasks: List[Dict[str, Any]],
        priority: TaskPriority = TaskPriority.NORMAL
    ) -> int:
        """Add multiple tasks at once. Returns count of tasks added."""
        added = 0
        for task_data in tasks:
            if await self.add_task(
                scanner_name=task_data['scanner_name'],
                scanner=task_data['scanner'],
                url=task_data['url'],
                params=task_data.get('params', {}),
                task_type=task_data.get('task_type', 'param'),
                priority=priority
            ):
                added += 1
        return added
    
    def _get_host_semaphore(self, host: str) -> asyncio.Semaphore:
        """Get or create semaphore for host"""
        if host not in self._host_semaphores:
            self._host_semaphores[host] = asyncio.Semaphore(self.max_per_host)
        return self._host_semaphores[host]
    
    async def _execute_task(self, session, task: ScanTask) -> TaskResult:
        """Execute a single scan task"""
        start_time = time.time()
        
        try:
            # Get host semaphore for per-host limiting
            host_sem = self._get_host_semaphore(task.host)
            
            async with host_sem:
                # Track running task
                task_key = self._get_task_key(task)
                self._running_tasks[task_key] = task
                self._host_running[task.host] += 1
                
                try:
                    # Execute with timeout
                    if task.task_type == "site":
                        vulns = await asyncio.wait_for(
                            task.scanner.scan(session, task.url),
                            timeout=self.task_timeout
                        )
                    else:
                        vulns = await asyncio.wait_for(
                            task.scanner.scan(session, task.url, task.params),
                            timeout=self.task_timeout
                        )
                    
                    duration = time.time() - start_time
                    
                    return TaskResult(
                        task=task,
                        vulnerabilities=vulns,
                        duration=duration,
                        success=True
                    )
                    
                finally:
                    # Cleanup tracking
                    self._running_tasks.pop(task_key, None)
                    self._host_running[task.host] -= 1
                    
        except asyncio.TimeoutError:
            return TaskResult(
                task=task,
                vulnerabilities=[],
                duration=time.time() - start_time,
                success=False,
                error=f"Timeout after {self.task_timeout}s"
            )
        except Exception as e:
            return TaskResult(
                task=task,
                vulnerabilities=[],
                duration=time.time() - start_time,
                success=False,
                error=str(e)
            )
    
    async def _worker(self, session, worker_id: int):
        """Worker coroutine that processes tasks from the queue"""
        while self._running:
            task = None
            
            async with self._lock:
                if self._task_queue:
                    task = heapq.heappop(self._task_queue)
            
            if task is None:
                await asyncio.sleep(0.1)
                continue
            
            # Execute the task
            result = await self._execute_task(session, task)
            
            # Handle result
            async with self._lock:
                task_key = self._get_task_key(task)
                
                if result.success:
                    self._completed_count += 1
                    self._results.append(result)
                    self._all_vulnerabilities.extend(result.vulnerabilities)
                    self._pending_tasks.discard(task_key)
                else:
                    # Retry logic
                    if task.retries < task.max_retries:
                        task.retries += 1
                        # Re-add with lower priority
                        task.priority += 1
                        await asyncio.sleep(self.retry_delay * task.retries)
                        heapq.heappush(self._task_queue, task)
                    else:
                        self._failed_count += 1
                        self._results.append(result)
                        self._pending_tasks.discard(task_key)
                
                # Progress callback
                if self._progress_callback:
                    total = self._completed_count + self._failed_count + len(self._task_queue)
                    completed = self._completed_count + self._failed_count
                    self._progress_callback(
                        completed,
                        total,
                        f"Worker {worker_id}: {task.scanner_name}"
                    )
                
                # Task complete callback
                if self._task_complete_callback:
                    self._task_complete_callback(result)
    
    async def run(self, session) -> List[Vulnerability]:
        """
        Run the scheduler until all tasks are complete.
        
        Args:
            session: aiohttp ClientSession
            
        Returns:
            List of all discovered vulnerabilities
        """
        self._running = True
        self._global_semaphore = asyncio.Semaphore(self.max_concurrent_tasks)
        
        # Start workers
        workers = [
            asyncio.create_task(self._worker(session, i))
            for i in range(self.max_concurrent_tasks)
        ]
        
        # Wait for queue to drain
        while self._task_queue or self._running_tasks:
            await asyncio.sleep(0.5)
        
        # Stop workers
        self._running = False
        await asyncio.sleep(0.2)  # Let workers finish their loops
        
        # Cancel any remaining workers
        for worker in workers:
            if not worker.done():
                worker.cancel()
        
        return self._all_vulnerabilities
    
    def get_stats(self) -> Dict:
        """Get scheduler statistics"""
        return {
            "completed": self._completed_count,
            "failed": self._failed_count,
            "pending": len(self._task_queue),
            "running": len(self._running_tasks),
            "total_vulnerabilities": len(self._all_vulnerabilities),
            "hosts_active": len([h for h, c in self._host_running.items() if c > 0])
        }
    
    def get_results(self) -> List[TaskResult]:
        """Get all task results"""
        return self._results


# Scanner priority mappings
SCANNER_PRIORITIES = {
    # Critical - Remote code execution possibilities
    'cmdi': TaskPriority.CRITICAL,
    'sqli': TaskPriority.CRITICAL,
    'ssti': TaskPriority.CRITICAL,
    
    # High - Significant security impact
    'xss': TaskPriority.HIGH,
    'ssrf': TaskPriority.HIGH,
    'nosqli': TaskPriority.HIGH,
    'path_traversal': TaskPriority.HIGH,
    
    # Normal - Standard vulnerability checks
    'idor': TaskPriority.NORMAL,
    'cors': TaskPriority.NORMAL,
    'headers': TaskPriority.NORMAL,
    
    # Low - Information gathering
    'debug': TaskPriority.LOW,
    'backup': TaskPriority.LOW,
    'forced_browsing': TaskPriority.LOW,
}


def get_scanner_priority(scanner_name: str) -> TaskPriority:
    """Get priority for a scanner"""
    return SCANNER_PRIORITIES.get(scanner_name, TaskPriority.NORMAL)