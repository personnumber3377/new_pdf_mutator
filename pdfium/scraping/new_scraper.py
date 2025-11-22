from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
import time

options = Options()
options.add_argument("--start-maximized")
options.add_argument("--disable-blink-features=AutomationControlled")
# options.add_argument("--user-data-dir=/home/oof/.config/google-chrome")  # <-- use your profile to stay logged in

driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

# BASE = "https://issues.chromium.org/issues?q=status:open%20componentid:1456345%20type:bug&p={page}"

BASE = "https://issues.chromium.org/issues?q=status:closed%20componentid:1456345%20Security&p={page}"

import requests
import re
import os
import random

def download_with_session(url, out_dir="corpus"):
    os.makedirs(out_dir, exist_ok=True)

    # Pull chrome cookies from Selenium for authentication
    cookies = {c['name']: c['value'] for c in driver.get_cookies()}

    # Follow redirects
    r = requests.get(url, cookies=cookies, allow_redirects=True)

    # Determine filename from Content-Disposition header (if present)
    cd = r.headers.get("Content-Disposition", "")
    m = re.search(r'filename="([^"]+)"', cd)
    if m:
        filename = m.group(1)
    else:
        # fallback: extract from URL
        filename = url.split("/")[-1].split("?")[0]
        if not filename.lower().endswith(".pdf"):
            filename += ".pdf"
    # path = os.path.join()
    path = os.path.join(out_dir, str(random.randrange(1_000_000))+"-"+filename)

    if r.status_code != 200:
        print(f"[!] HTTP {r.status_code} for {url}")
        return False

    # Save file
    with open(path, "wb") as f:
        f.write(r.content)

    size = len(r.content)
    print(f"[+] Saved {filename} ({size} bytes)")
    return True

def get_issue_links(page):
    url = BASE.format(page=page)
    driver.get(url)
    time.sleep(3)  # allow JS to load

    links = set()
    elems = driver.find_elements("css selector", "a[href*='issues/']")
    for e in elems:
        href = e.get_attribute("href")
        if "/issues/" in href and "/attachments/" not in href:
            links.add(href)

    return links

def get_attachments(issue_url):
    driver.get(issue_url)
    time.sleep(3)

    links = []
    elems = driver.find_elements("css selector", "a[href*='attachments/']")
    for e in elems:
        href = e.get_attribute("href")
        if "download=true" in href:
            links.append(href)
    return links

# print(get_issue_links(0))


all_issues = set()

for page in range(5000):                # scrape issue listing pages
    for issue in get_issue_links(page):
        attachments = get_attachments(issue)
        print("Here are the attachments: "+str(attachments))
        for att in attachments:
            download_with_session(att)

print("[*] Total collected:", len(all_issues))

driver.quit()
