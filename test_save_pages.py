import asyncio
from crawler.spider import AsyncWebCrawler

async def test():
    print("Testing crawler with page saving...")
    
    # Test on testphp.vulnweb.com (safe test site)
    crawler = AsyncWebCrawler(
        base_url="http://testphp.vulnweb.com",
        max_depth=3,
        max_pages=50,
        save_pages=True,
        output_dir="./saved_pages"
    )
    
    results = await crawler.crawl()
    
    print("\nDone!")
    print(f"Pages crawled: {results['total_pages']}")
    print(f"Forms found: {len(results['forms'])}")
    print("Saved files in: ./saved_pages/")
    
    # List the files
    import os
    if os.path.exists('./saved_pages'):
        files = [f for f in os.listdir('./saved_pages') if f.endswith('.html')]
        print(f"Total HTML files saved: {len(files)}")

asyncio.run(test())