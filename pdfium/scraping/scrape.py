import requests
import os
import hashlib
import time

OUTPUT_DIR = "pdfium_corpus"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Monorail API endpoint (public)
BASE_URL = "https://bugs.chromium.org/prpc/monorail.Issues/SearchIssues"
ATTACH_URL = "https://bugs.chromium.org/p/pdfium/issues/attachment?aid="

QUERY = "component=PDFium"  # Could also filter by status, etc.

SESSION = requests.Session()
SESSION.headers.update({
    "Content-Type": "application/json",
    "Accept": "application/json",
})

def sha256(buf):
    return hashlib.sha256(buf).hexdigest()

def download_attachment(aid):
    url = ATTACH_URL + str(aid)
    r = SESSION.get(url)
    if r.status_code != 200:
        print(f" !! Failed download {aid} ({r.status_code})")
        return
    
    digest = sha256(r.content)
    filename = os.path.join(OUTPUT_DIR, digest + ".pdf")

    if os.path.exists(filename):
        print(f" -- Skipping (duplicate): {aid}")
        return

    with open(filename, "wb") as f:
        f.write(r.content)

    print(f" [+] Saved: {filename}")

def scrape_page(page_token=None):
    payload = {
        "query": QUERY,
        "pageSize": 1000,
    }
    if page_token:
        payload["pageToken"] = page_token

    r = SESSION.post(BASE_URL, json=payload)
    if r.status_code != 200:
        print("Request failed", r.status_code, r.text)
        return None, None
    
    # Monorail wraps JSON in )]}'
    text = r.text.lstrip(")]}'")
    data = r.json()
    
    issues = data.get("issues", [])
    next_page = data.get("nextPageToken", None)

    return issues, next_page

def extract_attachments(issue):
    comments = issue.get("comments", [])
    for c in comments:
        attachments = c.get("attachments", [])
        for a in attachments:
            aid = a.get("attachmentId")
            name = a.get("filename", "")

            if name.lower().endswith(".pdf"):
                yield aid, name

def main():
    print("[*] Starting scrape...")
    token = None

    while True:
        issues, token = scrape_page(token)
        if not issues:
            break

        for issue in issues:
            issue_id = issue.get("localId")
            print(f"[+] Issue #{issue_id}")

            for aid, name in extract_attachments(issue):
                print(f"    -> downloading {name} (aid={aid})")
                download_attachment(aid)
                time.sleep(0.2)  # avoid hammering server

        if not token:
            break

    print("[*] Done.")

if __name__ == "__main__":
    main()
