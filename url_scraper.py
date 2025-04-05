import csv
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def scrape_urls(start_url, max_pages=10):
    unique_urls = set()
    
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            print(f"Navigating to {start_url}...")
            page.goto(start_url, timeout=60000)

            html_content = page.content()
            soup = BeautifulSoup(html_content, "html.parser")

            for link in soup.find_all("a", href=True):
                url = urljoin(start_url, link["href"])
                parsed_url = urlparse(url)

                if parsed_url.netloc == urlparse(start_url).netloc:
                    unique_urls.add(url)

                if len(unique_urls) >= max_pages:
                    break

            browser.close()

    except Exception as e:
        print(f"An error occurred: {e}")
        return []

    return list(unique_urls)


def save_to_csv(urls, filename="scraped_urls.csv"):
    try:
        with open(filename, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=["pattern", "type"])
            writer.writeheader()
            
            for url in urls:
                writer.writerow({"pattern": url, "type": "valid"})
        print(f"Saved {len(urls)} URLs to {filename}")

    except Exception as e:
        print(f"Failed to save to CSV: {e}")


if __name__ == "__main__":
    start_url = "https://www.usnews.com/"
    max_pages = 1000000

    urls = scrape_urls(start_url, max_pages=max_pages)
    name = "usnews.csv"
    save_to_csv(urls, filename=name)

    print(f"Scraped {len(urls)} URLs and saved to {name}")