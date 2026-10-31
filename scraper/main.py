import hashlib
import os
import re
import sys
import json
import unicodedata
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError
import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv

# ── UTF-8 output on Windows ───────────────────────────────────────────────────
if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

# ── Load .env (scraper dir or parent backend dir) ─────────────────────────────
load_dotenv()
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

# ── AWS / S3 config ───────────────────────────────────────────────────────────
AWS_REGION            = os.getenv("AWS_REGION", "ap-south-1")
AWS_S3_BUCKET         = os.getenv("AWS_S3_BUCKET")
AWS_ACCESS_KEY_ID     = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
SCRAPER_UPLOADER_ID   = os.getenv("SCRAPER_UPLOADER_ID", "scraper-bot")

if not AWS_S3_BUCKET:
    print("[Error] AWS_S3_BUCKET not set in environment. Check your .env file.")
    sys.exit(1)
if not AWS_ACCESS_KEY_ID or not AWS_SECRET_ACCESS_KEY:
    print("[Error] AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY not set. Check your .env file.")
    sys.exit(1)

print(f"[S3] Connecting to bucket '{AWS_S3_BUCKET}' in region '{AWS_REGION}'...")
s3 = boto3.client(
    "s3",
    region_name=AWS_REGION,
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
)

# S3 key prefixes — must match backend/services/s3Storage.js
NOTE_FILE_PREFIX     = "notes/"      # actual PDF files
NOTE_METADATA_PREFIX = "metadata/"   # JSON metadata records

# ── Scraper constants ─────────────────────────────────────────────────────────
BASE_URL = "https://getmaterials.in"
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

DOWNLOAD_DIR = os.path.join(os.path.dirname(__file__), "downloaded_pdfs")
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

# ── In-memory duplicate index ─────────────────────────────────────────────────
# Loaded once at startup from S3; updated on every successful upload.
# Stores note_id strings — keyed off title+filename so lookups are O(1).
_existing_note_ids: set[str] = set()
# Maps "title||filename" → note_id for content-based duplicate detection
_existing_note_keys: set[str] = set()


def _make_note_key(title: str, filename: str) -> str:
    """Stable string key combining title and filename for duplicate detection."""
    return f"{title.strip().lower()}||{filename.strip().lower()}"


def load_existing_notes_from_s3() -> None:
    """
    Scan all metadata/*.json objects in the bucket once at startup and
    populate the in-memory duplicate index.  This avoids a head_object
    round-trip for every PDF during the run.
    """
    print("[S3] Loading existing note index from bucket (this may take a moment)...")
    count = 0
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=AWS_S3_BUCKET, Prefix=NOTE_METADATA_PREFIX):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            note_id = key[len(NOTE_METADATA_PREFIX):].removesuffix(".json")
            if not note_id:
                continue
            _existing_note_ids.add(note_id)
            # Fetch the record to extract title + fileName for content-based check
            try:
                result = s3.get_object(Bucket=AWS_S3_BUCKET, Key=key)
                record = json.loads(result["Body"].read())
                note_key = _make_note_key(
                    record.get("title", ""),
                    record.get("fileName", ""),
                )
                _existing_note_keys.add(note_key)
                count += 1
            except Exception:
                # If we can't read the record, at least we have the note_id
                count += 1

    print(f"[S3] Index loaded — {count} existing note(s) found.\n")


# ── S3 helpers ────────────────────────────────────────────────────────────────

def upload_pdf_to_s3(pdf_bytes: bytes, s3_key: str, filename: str) -> None:
    """Upload a PDF binary to S3."""
    s3.put_object(
        Bucket=AWS_S3_BUCKET,
        Key=s3_key,
        Body=pdf_bytes,
        ContentType="application/pdf",
        ContentDisposition=f'attachment; filename="{filename}"',
        ServerSideEncryption="AES256",
    )
    print(f"  [S3] Uploaded PDF     → s3://{AWS_S3_BUCKET}/{s3_key}")


def put_note_record(note: dict) -> None:
    """Write a note metadata JSON to S3 — mirrors s3Storage.putNoteRecord()."""
    metadata_key = f"{NOTE_METADATA_PREFIX}{note['_id']}.json"
    s3.put_object(
        Bucket=AWS_S3_BUCKET,
        Key=metadata_key,
        Body=json.dumps(note, ensure_ascii=False),
        ContentType="application/json",
        ServerSideEncryption="AES256",
    )
    print(f"  [S3] Saved metadata   → s3://{AWS_S3_BUCKET}/{metadata_key}")


# ── Helpers ───────────────────────────────────────────────────────────────────

def to_s3_segment(value: str, fallback: str = "note", max_len: int = 80) -> str:
    """Convert any string to a safe lowercase S3 path segment."""
    normalized = unicodedata.normalize("NFKD", value or "")
    ascii_str  = normalized.encode("ascii", "ignore").decode("ascii")
    slug       = re.sub(r"[^a-z0-9]+", "-", ascii_str.lower()).strip("-")
    return (slug or fallback)[:max_len].rstrip("-")


def make_deterministic_note_id(title: str, filename: str) -> str:
    """
    Build a stable, deterministic note ID from title + filename.
    Using a hash means the same PDF always produces the same ID, so the
    metadata key lookup is a reliable duplicate check without a UUID.
    """
    title_slug    = to_s3_segment(title, "note", 60)
    filename_slug = to_s3_segment(filename.replace(".pdf", ""), "file", 40)
    content_hash  = hashlib.sha1(
        f"{title.strip().lower()}||{filename.strip().lower()}".encode()
    ).hexdigest()[:12]
    return f"{title_slug}-{filename_slug}-{content_hash}"


# ── HTML extraction helpers ───────────────────────────────────────────────────

def extract_title_from_html(soup: BeautifulSoup, default_title: str = "Untitled Note") -> str:
    h1 = soup.find("h1")
    if h1:
        h1_copy = BeautifulSoup(str(h1), "html.parser").find("h1")
        for extra in h1_copy.find_all(["span", "button", "svg"]):
            extra.decompose()
        text = h1_copy.get_text(" ", strip=True)
        if text:
            return text
    if soup.title and soup.title.string:
        clean = soup.title.string.replace("- GetMaterials", "").strip()
        if clean:
            return clean
    return default_title


def extract_metadata_from_html(soup: BeautifulSoup) -> dict:
    description = ""
    about_heading = soup.find(
        lambda el: el.name in ["h2", "h3"] and "about" in el.get_text().lower()
    )
    if about_heading:
        sibling = about_heading.find_next_sibling()
        if sibling:
            description = sibling.get_text(" ", strip=True)

    category = ""
    cat_span = soup.find(
        "span", class_=lambda c: c and ("bg-violet-50" in c or "rounded-lg" in c)
    )
    if cat_span:
        category = cat_span.get_text(strip=True)

    university = ""
    course     = category or ""
    year       = None

    for div in soup.find_all("div", class_=lambda c: c and "flex items-center gap-2" in c):
        text       = div.get_text(" ", strip=True)
        svg        = div.find("svg")
        svg_classes = " ".join(svg.get("class", [])) if svg else ""

        if "school" in svg_classes:
            university = text
        elif "graduation-cap" in svg_classes:
            parts = [p.strip() for p in text.split("·") if p.strip()]
            for part in parts:
                year_match = re.search(r"(\d+)", part)
                if year_match and ("year" in part.lower() or "sem" in part.lower()):
                    year = int(year_match.group(1))
                elif not course or course == category:
                    course = part

    return {
        "description": description,
        "category":    category,
        "university":  university,
        "course":      course,
        "year":        year,
    }


def infer_study_type(title: str) -> str:
    lower = title.lower()
    if "assignment" in lower:
        return "Assignments"
    if "question bank" in lower or "que bank" in lower or "question paper" in lower:
        return "Que Banks"
    if "paper" in lower or "pyq" in lower or "mid" in lower or "exam" in lower:
        return "Papers"
    if "ppt" in lower or "presentation" in lower or "slide" in lower:
        return "PPT"
    if "lab" in lower or "manual" in lower:
        return "Lab Manual"
    if "syllabus" in lower:
        return "Syllabus"
    return "Notes"


# ── Core upload function ──────────────────────────────────────────────────────

def upload_note_to_s3(
    pdf_bytes:   bytes,
    filename:    str,
    title:       str,
    description: str,
    university:  str,
    course:      str,
    category:    str,
    study_type:  str,
    year,
    tags:        list,
) -> str | None:
    """
    Check for duplicates, then upload PDF + metadata to S3.

    Duplicate detection (two layers):
      1. Content key  — title + filename combination (catches re-runs after
                        the index is warm).
      2. note_id key  — deterministic hash-based ID checked against the
                        in-memory set (fast, no S3 round-trip).

    Returns the note_id on success, or None if the note was skipped.

    S3 layout (mirrors the backend):
      notes/<uploader-slug>/<note-id>    ← actual PDF
      metadata/<note-id>.json            ← note record (read by the API)
    """
    note_key = _make_note_key(title, filename)
    note_id  = make_deterministic_note_id(title, filename)

    # ── Layer 1: content-based duplicate check (in-memory, O(1)) ─────────────
    if note_key in _existing_note_keys:
        print(f"  [Skipped] Already exists — same title + filename: '{title}'")
        return None

    # ── Layer 2: note_id duplicate check (in-memory, O(1)) ───────────────────
    if note_id in _existing_note_ids:
        print(f"  [Skipped] Already exists — note_id: {note_id}")
        _existing_note_keys.add(note_key)   # keep index consistent
        return None

    # ── Upload PDF ────────────────────────────────────────────────────────────
    uploader_slug = to_s3_segment(SCRAPER_UPLOADER_ID, "scraper", 60)
    s3_key        = f"{NOTE_FILE_PREFIX}{uploader_slug}/{note_id}"
    upload_pdf_to_s3(pdf_bytes, s3_key, filename)

    # ── Write metadata record ─────────────────────────────────────────────────
    now = datetime.now(timezone.utc).isoformat()
    note_record = {
        "_id":             note_id,
        "title":           title,
        "description":     description or "",
        "fileName":        filename,
        "s3Key":           s3_key,
        "storageProvider": "s3",
        "contentType":     "application/pdf",
        "fileSize":        len(pdf_bytes),
        "university":      university or "",
        "course":          course or "",
        "subject":         "",
        "category":        category or study_type or "",
        "studyType":       study_type or "Notes",
        "year":            year,
        "tags":            tags or [],
        "uploadedBy":      SCRAPER_UPLOADER_ID,
        "visibility":      "public",
        "uploadStatus":    "active",
        "createdAt":       now,
        "updatedAt":       now,
    }
    put_note_record(note_record)

    # ── Update in-memory index so later iterations see this note ──────────────
    _existing_note_ids.add(note_id)
    _existing_note_keys.add(note_key)

    return note_id


# ── Main scraper loop ─────────────────────────────────────────────────────────

def scrape_materials():
    # Counters
    added   = 0
    skipped = 0

    page_num = 1
    session  = requests.Session()

    while True:
        print(f"\n--- Scraping Page {page_num} ---")
        res = session.get(
            f"{BASE_URL}/materials",
            headers=HEADERS,
            params={"page": page_num},
            timeout=30,
        )

        if res.status_code != 200:
            print(f"[Error] Failed to fetch page {page_num}: HTTP {res.status_code}")
            break

        soup    = BeautifulSoup(res.text, "html.parser")
        content = soup.find("div", class_="mt-6")

        if not content:
            print("No material container found. Stopping.")
            break
        if content.find(string=lambda t: t and "No materials match your filters." in t):
            print("Reached end of materials. Stopping.")
            break

        cards = content.find_all("a")
        if not cards:
            print("No more cards found.")
            break

        print(f"Found {len(cards)} items on page {page_num}.")

        for card in cards:
            link = card.get("href")
            if not link:
                continue

            material_url = BASE_URL + link
            print(f"\nProcessing: {material_url}")

            try:
                page_res = session.get(material_url, headers=HEADERS, timeout=30)
                if page_res.status_code != 200:
                    print(f"  Failed to load detail page: HTTP {page_res.status_code}")
                    continue

                detail_soup = BeautifulSoup(page_res.text, "html.parser")

                title      = extract_title_from_html(detail_soup)
                meta       = extract_metadata_from_html(detail_soup)
                study_type = infer_study_type(title)
                print(f"  Title: {title}")

                tags = []
                if meta["category"]:
                    tags.append(meta["category"])
                if meta["course"] and meta["course"] not in tags:
                    tags.append(meta["course"])
                if study_type not in tags:
                    tags.append(study_type)

                # Find PDF download links
                download_buttons = detail_soup.select("a[download]")
                if not download_buttons:
                    print("  No download buttons found.")
                    continue

                pdf_links = []
                for btn in download_buttons:
                    href = btn.get("href")
                    if not href:
                        continue
                    clean_path = href.split("?")[0].lower()
                    if (clean_path.endswith(".pdf") or "pdf" in clean_path) and href not in pdf_links:
                        pdf_links.append(href)

                if not pdf_links:
                    print("  No PDF links found.")
                    continue

                for download_link in pdf_links:
                    raw_filename = download_link.split("/")[-1].split("?")[0]
                    filename     = requests.utils.unquote(raw_filename)
                    if not filename.lower().endswith(".pdf"):
                        filename += ".pdf"

                    note_title = title
                    if len(pdf_links) > 1:
                        stem = filename.replace(".pdf", "").replace("_", " ").strip()
                        if stem and stem.lower() not in title.lower():
                            note_title = f"{title} - {stem}"

                    # ── Duplicate check BEFORE downloading ────────────────────
                    note_key = _make_note_key(note_title, filename)
                    note_id  = make_deterministic_note_id(note_title, filename)
                    if note_key in _existing_note_keys or note_id in _existing_note_ids:
                        print(f"  [Skipped] Duplicate detected before download: '{note_title}'")
                        skipped += 1
                        continue

                    print(f"  Downloading: {download_link}")
                    pdf_res = session.get(download_link, headers=HEADERS, timeout=60)
                    pdf_res.raise_for_status()
                    pdf_bytes = pdf_res.content

                    # Save a local copy
                    local_path = os.path.join(DOWNLOAD_DIR, filename)
                    with open(local_path, "wb") as f:
                        f.write(pdf_bytes)
                    print(f"  Saved locally: {local_path}")

                    # Upload to S3
                    result_id = upload_note_to_s3(
                        pdf_bytes   = pdf_bytes,
                        filename    = filename,
                        title       = note_title,
                        description = meta["description"],
                        university  = meta["university"],
                        course      = meta["course"],
                        category    = meta["category"],
                        study_type  = study_type,
                        year        = meta["year"],
                        tags        = tags,
                    )

                    if result_id:
                        added += 1
                        print(f"  [Added]   note_id: {result_id}  (added={added}, skipped={skipped})")
                    else:
                        skipped += 1
                        print(f"  [Skipped] (added={added}, skipped={skipped})")

            except Exception as err:
                print(f"  [Error] {material_url}: {err}")

        page_num += 1

    # ── Final summary ─────────────────────────────────────────────────────────
    print("\n" + "=" * 50)
    print("  SCRAPE COMPLETE")
    print(f"  Added   : {added}")
    print(f"  Skipped : {skipped}")
    print(f"  Total   : {added + skipped}")
    print("=" * 50)


if __name__ == "__main__":
    # Load the existing note index from S3 before scraping
    load_existing_notes_from_s3()
    scrape_materials()
