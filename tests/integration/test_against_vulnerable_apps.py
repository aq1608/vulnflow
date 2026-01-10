# tests/integration/test_against_vulnerable_apps.py
import pytest
import asyncio
import subprocess
import time
import requests

class TestAgainstDVWA:
    """Integration tests against DVWA"""
    
    @pytest.fixture(scope="class")
    def dvwa_container(self):
        """Start DVWA container for testing"""
        # Start container
        subprocess.run([
            "docker", "run", "-d", 
            "--name", "dvwa-test",
            "-p", "8888:80",
            "vulnerables/web-dvwa"
        ], check=True)
        
        # Wait for container to be ready
        for _ in range(30):
            try:
                resp = requests.get("http://localhost:8888")
                if resp.status_code == 200:
                    break
            except:
                pass
            time.sleep(1)
        
        yield "http://localhost:8888"
        
        # Cleanup
        subprocess.run(["docker", "rm", "-f", "dvwa-test"])
    
    @pytest.mark.asyncio
    async def test_detects_sqli_in_dvwa(self, dvwa_container):
        """Should detect SQL injection in DVWA"""
        from scanner.vuln_scanner import VulnerabilityScanner
        from crawler.spider import AsyncWebCrawler
        
        # Login to DVWA first (default: admin/password)
        session = requests.Session()
        session.post(f"{dvwa_container}/login.php", data={
            "username": "admin",
            "password": "password",
            "Login": "Login"
        })
        
        # Set security level to low
        session.post(f"{dvwa_container}/security.php", data={
            "security": "low"
        })
        
        # Scan the SQLi page
        scanner = VulnerabilityScanner()
        target = {
            "url": f"{dvwa_container}/vulnerabilities/sqli/",
            "params": {"id": "1", "Submit": "Submit"}
        }
        
        vulns = await scanner.scan_target({"forms": [], "urls": {target["url"]: {}}})
        
        sqli_vulns = [v for v in vulns if "SQL" in v.vuln_type]
        assert len(sqli_vulns) > 0, "Should detect SQLi in DVWA"


class TestAgainstJuiceShop:
    """Integration tests against OWASP Juice Shop"""
    
    @pytest.fixture(scope="class")
    def juice_shop_container(self):
        """Start Juice Shop container"""
        subprocess.run([
            "docker", "run", "-d",
            "--name", "juice-shop-test",
            "-p", "3333:3000",
            "bkimminich/juice-shop"
        ], check=True)
        
        # Wait for startup
        for _ in range(60):
            try:
                resp = requests.get("http://localhost:3333")
                if resp.status_code == 200:
                    break
            except:
                pass
            time.sleep(1)
        
        yield "http://localhost:3333"
        
        subprocess.run(["docker", "rm", "-f", "juice-shop-test"])
    
    @pytest.mark.asyncio
    async def test_full_scan_juice_shop(self, juice_shop_container):
        """Run full scan against Juice Shop"""
        from crawler.spider import AsyncWebCrawler
        from scanner.vuln_scanner import VulnerabilityScanner
        
        # Crawl
        crawler = AsyncWebCrawler(juice_shop_container, max_depth=2, max_pages=50)
        crawl_results = await crawler.crawl()
        
        assert len(crawl_results["urls"]) > 0, "Should crawl pages"
        
        # Scan
        scanner = VulnerabilityScanner()
        vulns = await scanner.scan_target(crawl_results)
        
        # Juice Shop has many known vulnerabilities
        assert len(vulns) > 0, "Should find vulnerabilities in Juice Shop"
        
        # Check for expected vulnerability types
        vuln_types = set(v.vuln_type for v in vulns)
        print(f"Found vulnerability types: {vuln_types}")