"""Async utilities for parallel scanning"""

import asyncio
import aiohttp
from typing import List, TypeVar, Callable, Any, Optional, Dict
from functools import wraps
import time
from dataclasses import dataclass, field
from collections import defaultdict

T = TypeVar('T')


class AsyncBatcher:
    """Batch async operations for efficient execution"""
    
    def __init__(self, batch_size: int = 10, delay_between_batches: float = 0.1):
        self.batch_size = batch_size
        self.delay = delay_between_batches
    
    async def execute(
        self, 
        items: List[Any], 
        async_func: Callable,
        *args, 
        **kwargs
    ) -> List[Any]:
        """Execute async function on items in batches"""
        results = []
        
        for i in range(0, len(items), self.batch_size):
            batch = items[i:i + self.batch_size]
            batch_tasks = [async_func(item, *args, **kwargs) for item in batch]
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            results.extend(batch_results)
            
            if i + self.batch_size < len(items):
                await asyncio.sleep(self.delay)
        
        return results


class AsyncRetry:
    """Retry decorator for async functions"""
    
    def __init__(
        self, 
        max_retries: int = 3, 
        delay: float = 1.0,
        backoff: float = 2.0,
        exceptions: tuple = (Exception,)
    ):
        self.max_retries = max_retries
        self.delay = delay
        self.backoff = backoff
        self.exceptions = exceptions
    
    def __call__(self, func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            delay = self.delay
            
            for attempt in range(self.max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except self.exceptions as e:
                    last_exception = e
                    if attempt < self.max_retries:
                        await asyncio.sleep(delay)
                        delay *= self.backoff
            
            raise last_exception
        
        return wrapper


class AsyncTimeout:
    """Context manager for async timeouts with cleanup"""
    
    def __init__(self, timeout: float, cleanup_func: Optional[Callable] = None):
        self.timeout = timeout
        self.cleanup_func = cleanup_func
        self._task = None
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type is asyncio.TimeoutError and self.cleanup_func:
            await self.cleanup_func()
        return False
    
    async def run(self, coro):
        """Run coroutine with timeout"""
        return await asyncio.wait_for(coro, timeout=self.timeout)


class TaskQueue:
    """Priority task queue for scan tasks"""
    
    def __init__(self, max_size: int = 1000):
        self._queue = asyncio.PriorityQueue(maxsize=max_size)
        self._counter = 0
    
    async def put(self, item: Any, priority: int = 5):
        """Add item with priority (lower = higher priority)"""
        self._counter += 1
        await self._queue.put((priority, self._counter, item))
    
    async def get(self) -> Any:
        """Get highest priority item"""
        priority, counter, item = await self._queue.get()
        return item
    
    def task_done(self):
        """Mark task as done"""
        self._queue.task_done()
    
    async def join(self):
        """Wait for all tasks to complete"""
        await self._queue.join()
    
    def empty(self) -> bool:
        """Check if queue is empty"""
        return self._queue.empty()
    
    def qsize(self) -> int:
        """Get queue size"""
        return self._queue.qsize()


async def gather_with_concurrency(
    n: int, 
    *coros,
    return_exceptions: bool = True
) -> List[Any]:
    """
    Like asyncio.gather but with a concurrency limit.
    
    Args:
        n: Maximum concurrent coroutines
        *coros: Coroutines to execute
        return_exceptions: Whether to return exceptions or raise them
    """
    semaphore = asyncio.Semaphore(n)
    
    async def sem_coro(coro):
        async with semaphore:
            return await coro
    
    return await asyncio.gather(
        *(sem_coro(c) for c in coros),
        return_exceptions=return_exceptions
    )


@dataclass
class ScanMetrics:
    """Metrics collection for scan operations"""
    
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_vulnerabilities: int = 0
    scanner_times: Dict[str, float] = field(default_factory=dict)
    request_times: List[float] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    def record_request(self, duration: float, success: bool = True):
        """Record a request"""
        self.total_requests += 1
        self.request_times.append(duration)
        if success:
            self.successful_requests += 1
        else:
            self.failed_requests += 1
    
    def record_scanner_time(self, scanner_name: str, duration: float):
        """Record scanner execution time"""
        if scanner_name not in self.scanner_times:
            self.scanner_times[scanner_name] = 0
        self.scanner_times[scanner_name] += duration
    
    def record_error(self, error: str):
        """Record an error"""
        self.errors.append(error)
    
    def finalize(self):
        """Finalize metrics"""
        self.end_time = time.time()
    
    @property
    def duration(self) -> float:
        """Get total duration"""
        end = self.end_time or time.time()
        return end - self.start_time
    
    @property
    def avg_request_time(self) -> float:
        """Get average request time"""
        if not self.request_times:
            return 0
        return sum(self.request_times) / len(self.request_times)
    
    @property
    def requests_per_second(self) -> float:
        """Get requests per second"""
        if self.duration == 0:
            return 0
        return self.total_requests / self.duration
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "duration": self.duration,
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "avg_request_time": self.avg_request_time,
            "requests_per_second": self.requests_per_second,
            "total_vulnerabilities": self.total_vulnerabilities,
            "scanner_times": self.scanner_times,
            "error_count": len(self.errors)
        }


class ConnectionPool:
    """Managed connection pool for HTTP requests"""
    
    def __init__(
        self,
        max_connections: int = 100,
        max_connections_per_host: int = 10,
        ttl_dns_cache: int = 300,
        enable_cleanup: bool = True
    ):
        self.max_connections = max_connections
        self.max_connections_per_host = max_connections_per_host
        self.ttl_dns_cache = ttl_dns_cache
        self.enable_cleanup = enable_cleanup
        self._connector = None
        self._session = None
    
    async def get_session(self) -> 'aiohttp.ClientSession':
        """Get or create HTTP session"""
        
        if self._session is None or self._session.closed:
            self._connector = aiohttp.TCPConnector(
                limit=self.max_connections,
                limit_per_host=self.max_connections_per_host,
                ttl_dns_cache=self.ttl_dns_cache,
                ssl=False,
                enable_cleanup_closed=self.enable_cleanup
            )
            
            timeout = aiohttp.ClientTimeout(total=60, connect=10)
            
            self._session = aiohttp.ClientSession(
                connector=self._connector,
                timeout=timeout,
                headers={
                    'User-Agent': 'VulnFlow/2.0.1 Security Scanner',
                    'Accept': '*/*',
                    'Accept-Language': 'en-US,en;q=0.9',
                }
            )
        
        return self._session
    
    async def close(self):
        """Close the connection pool"""
        if self._session and not self._session.closed:
            await self._session.close()
        if self._connector:
            await self._connector.close()
    
    async def __aenter__(self):
        return await self.get_session()
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


class HostRateLimiter:
    """Per-host rate limiting to avoid overwhelming individual servers"""
    
    def __init__(self, default_rate: float = 10.0):
        self.default_rate = default_rate
        self._limiters: Dict[str, 'TokenBucket'] = {}
        self._lock = asyncio.Lock()
    
    async def acquire(self, host: str):
        """Acquire a token for the specified host"""
        async with self._lock:
            if host not in self._limiters:
                self._limiters[host] = TokenBucket(self.default_rate)
        
        await self._limiters[host].acquire()
    
    def set_rate(self, host: str, rate: float):
        """Set rate limit for a specific host"""
        self._limiters[host] = TokenBucket(rate)


class TokenBucket:
    """Token bucket implementation for rate limiting"""
    
    def __init__(self, rate: float, capacity: Optional[float] = None):
        self.rate = rate
        self.capacity = capacity or rate
        self.tokens = self.capacity
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()
    
    async def acquire(self, tokens: float = 1.0):
        """Acquire tokens, waiting if necessary"""
        async with self._lock:
            await self._wait_for_tokens(tokens)
            self.tokens -= tokens
    
    async def _wait_for_tokens(self, tokens: float):
        """Wait until enough tokens are available"""
        while True:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_update = now
            
            if self.tokens >= tokens:
                return
            
            wait_time = (tokens - self.tokens) / self.rate
            await asyncio.sleep(wait_time)


class CircuitBreaker:
    """Circuit breaker pattern for failing fast on problematic hosts"""
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_requests: int = 3
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_requests = half_open_requests
        
        self._failures: Dict[str, int] = defaultdict(int)
        self._last_failure: Dict[str, float] = {}
        self._state: Dict[str, str] = defaultdict(lambda: "closed")
        self._half_open_count: Dict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()
    
    async def can_execute(self, host: str) -> bool:
        """Check if request can be executed for host"""
        async with self._lock:
            state = self._state[host]
            
            if state == "closed":
                return True
            
            if state == "open":
                # Check if recovery timeout has passed
                if time.time() - self._last_failure.get(host, 0) > self.recovery_timeout:
                    self._state[host] = "half-open"
                    self._half_open_count[host] = 0
                    return True
                return False
            
            if state == "half-open":
                if self._half_open_count[host] < self.half_open_requests:
                    self._half_open_count[host] += 1
                    return True
                return False
            
            return True
    
    async def record_success(self, host: str):
        """Record successful request"""
        async with self._lock:
            if self._state[host] == "half-open":
                self._state[host] = "closed"
            self._failures[host] = 0
    
    async def record_failure(self, host: str):
        """Record failed request"""
        async with self._lock:
            self._failures[host] += 1
            self._last_failure[host] = time.time()
            
            if self._failures[host] >= self.failure_threshold:
                self._state[host] = "open"
            
            if self._state[host] == "half-open":
                self._state[host] = "open"
    
    def get_state(self, host: str) -> str:
        """Get circuit state for host"""
        return self._state[host]


async def run_with_semaphore(
    semaphore: asyncio.Semaphore,
    coro,
    timeout: Optional[float] = None
):
    """Run coroutine with semaphore and optional timeout"""
    async with semaphore:
        if timeout:
            return await asyncio.wait_for(coro, timeout=timeout)
        return await coro


def chunk_list(lst: List[T], chunk_size: int) -> List[List[T]]:
    """Split list into chunks"""
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]


async def async_map(
    func: Callable,
    items: List[Any],
    concurrency: int = 10,
    return_exceptions: bool = True
) -> List[Any]:
    """Map async function over items with concurrency limit"""
    semaphore = asyncio.Semaphore(concurrency)
    
    async def bounded_func(item):
        async with semaphore:
            return await func(item)
    
    tasks = [bounded_func(item) for item in items]
    return await asyncio.gather(*tasks, return_exceptions=return_exceptions)