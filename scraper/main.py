import os
import re
import sys
from datetime import datetime, timezone
import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from pymongo import MongoClient
from gridfs import GridFSBucket
import dns.resolver

# Configure UTF-8 output for Windows console
if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

# Configure DNS fallback for MongoDB Atlas SRV resolution on Windows
try:
    dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
    dns.resolver.default_resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
except Exception as e:
    print(f"[Warning] Could not set custom DNS nameservers: {e}")

# Load environment variables (.env in current or parent directory)
load_dotenv()
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    print("[Error] MONGO_URI not found in environment variables. Please check your .env file.")
    sys.exit(1)

# Connect to MongoDB
print("[MongoDB] Connecting to database...")
mongo_client = MongoClient(MONGO_URI)
try:
    db = mongo_client.get_default_database()
except Exception:
    db = mongo_client["test"]
notes_collection = db["notes"]
users_collection = db["users"]
gridfs_bucket = GridFSBucket(db, bucket_name="noteFiles")

# Resolve default uploader user ID
uploader_user_id = None
default_user_env = os.getenv("SCRAPER_USER_ID") or os.getenv("DEFAULT_USER_ID")
if default_user_env:
    from bson import ObjectId
    try:
        uploader_user_id = ObjectId(default_user_env)
    except Exception:
        uploader_user_id = None

if not uploader_user_id:
    first_user = users_collection.find_one()
    if first_user:
        uploader_user_id = first_user["_id"]
        print(f"[MongoDB] Using existing user as uploader: {first_user.get('name', 'User')} ({uploader_user_id})")
    else:
        print("[MongoDB] No user found in users collection. Notes will be created without uploadedBy.")

BASE_URL = "https://getmaterials.in"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

DOWNLOAD_DIR = os.path.join(os.path.dirname(__file__), "downloaded_pdfs")
os.makedirs(DOWNLOAD_DIR, exist_ok=True)


def extract_title_from_html(soup: BeautifulSoup, default_title: str = "Untitled Note") -> str:
    """Extract clean title from the HTML detail page response."""
    h1 = soup.find("h1")
    if h1:
        # Clone to avoid mutating original tree
        h1_copy = BeautifulSoup(str(h1), "html.parser").find("h1")
        # Remove inner badges (e.g., 'Free', 'Pro', icons, buttons)
        for extra in h1_copy.find_all(["span", "button", "svg"]):
            extra.decompose()
        title_text = h1_copy.get_text(" ", strip=True)
        if title_text:
            return title_text

    # Fallback to <title> tag
    if soup.title and soup.title.string:
        clean = soup.title.string.replace("- GetMaterials", "").strip()
        if clean:
            return clean

    return default_title


def extract_metadata_from_html(soup: BeautifulSoup) -> dict:
    """Extract description, university, course, studyType, year, and tags from HTML."""
    # 1. Description
    description = ""
    about_heading = soup.find(lambda el: el.name in ["h2", "h3"] and "about" in el.get_text().lower())
    if about_heading:
        sibling = about_heading.find_next_sibling()
        if sibling:
            description = sibling.get_text(" ", strip=True)

    # 2. Category badge (e.g. 'Robotics', 'Computer Science')
    category = ""
    cat_span = soup.find("span", class_=lambda c: c and ("bg-violet-50" in c or "rounded-lg" in c))
    if cat_span:
        category = cat_span.get_text(strip=True)

    # 3. Grid details (University, Year, Course/Branch)
    university = ""
    course = category or ""
    year = None

    for div in soup.find_all("div", class_=lambda c: c and "flex items-center gap-2" in c):
        text = div.get_text(" ", strip=True)
        svg = div.find("svg")
        svg_classes = " ".join(svg.get("class", [])) if svg else ""

        if "school" in svg_classes:
            university = text
        elif "graduation-cap" in svg_classes:
            # Format often: '2nd Year · ECE · EEE'
            parts = [p.strip() for p in text.split("·") if p.strip()]
            for part in parts:
                year_match = re.search(r"(\d+)", part)
                if year_match and ("year" in part.lower() or "sem" in part.lower()):
                    year = int(year_match.group(1))
                elif not course or course == category:
                    course = part

    return {
        "description": description,
        "category": category,
        "university": university,
        "course": course,
        "year": year,
    }


def infer_study_type(title: str) -> str:
    """Infer studyType based on title content."""
    lower = title.lower()
    if "assignment" in lower:
        return "Assignments"
    elif "question bank" in lower or "que bank" in lower or "question paper" in lower:
        return "Que Banks"
    elif "paper" in lower or "pyq" in lower or "mid" in lower or "exam" in lower:
        return "Papers"
    elif "ppt" in lower or "presentation" in lower or "slide" in lower:
        return "PPT"
    elif "lab" in lower or "manual" in lower:
        return "Lab Manual"
    elif "syllabus" in lower:
        return "Syllabus"
    return "Notes"


def upload_pdf_to_mongodb(
    pdf_bytes: bytes,
    filename: str,
    title: str,
    description: str,
    university: str,
    course: str,
    study_type: str,
    year: int,
    tags: list,
    uploader_id,
):
    """Store PDF file in GridFS bucket and insert document in 'notes' collection."""
    # Check if already exists in MongoDB by fileName and title
    existing_note = notes_collection.find_one({"fileName": filename, "title": title})
    if existing_note:
        print(f"  [Skipped] Note already exists in DB: '{title}' ({filename})")
        return existing_note["_id"]

    # 1. Store in GridFSBucket 'noteFiles'
    file_id = gridfs_bucket.upload_from_stream(
        filename,
        pdf_bytes,
        metadata={"contentType": "application/pdf"}
    )
    print(f"  [GridFS] Saved file into 'noteFiles' with fileId: {file_id}")

    # 2. Create document for 'notes' collection matching Note schema
    now = datetime.now(timezone.utc)
    note_doc = {
        "title": title,
        "description": description or "",
        "fileId": file_id,
        "fileName": filename,
        "contentType": "application/pdf",
        "fileSize": len(pdf_bytes),
        "university": university or "",
        "course": course or "",
        "studyType": study_type or "Notes",
        "year": year,
        "uploadedBy": uploader_id,
        "tags": tags or [],
        "createdAt": now,
        "updatedAt": now,
        "__v": 0,
    }

    result = notes_collection.insert_one(note_doc)
    print(f"  [MongoDB] Note document inserted successfully! ID: {result.inserted_id}")
    return result.inserted_id


def scrape_materials():
    page_num = 1
    session = requests.Session()

    while True:
        print(f"\n--- Scraping Page {page_num} ---")
        res = session.get(
            f"{BASE_URL}/materials",
            headers=HEADERS,
            params={"page": page_num},
            timeout=30,
        )

        if res.status_code != 200:
            print(f"[Error] Failed to fetch page {page_num}: Status {res.status_code}")
            break

        soup = BeautifulSoup(res.text, "html.parser") 
        content = soup.find("div", class_="mt-6")

        if not content:
            print("No material container found. Stopping.")
            break

        if content.find(string=lambda text: text and "No materials match your filters." in text):
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
                    print(f"  Failed to load detail page: Status {page_res.status_code}")
                    continue

                detail_soup = BeautifulSoup(page_res.text, "html.parser")

                # 1. Extract Title from HTML response
                title = extract_title_from_html(detail_soup)
                print(f"  Extracted Title: {title}")

                # 2. Extract Metadata from HTML
                meta = extract_metadata_from_html(detail_soup)
                study_type = infer_study_type(title)

                tags = []
                if meta["category"]:
                    tags.append(meta["category"])
                if meta["course"] and meta["course"] not in tags:
                    tags.append(meta["course"])
                if study_type and study_type not in tags:
                    tags.append(study_type)

                # 3. Find PDF download links
                download_buttons = detail_soup.select("a[download]")
                if not download_buttons:
                    print("  No download buttons found on page.")
                    continue

                # Collect unique PDF download links
                pdf_links = []
                for btn in download_buttons:
                    href = btn.get("href")
                    if not href:
                        continue
                    # Check if file is PDF
                    clean_path = href.split("?")[0].lower()
                    if clean_path.endswith(".pdf") or "pdf" in clean_path:
                        if href not in pdf_links:
                            pdf_links.append(href)

                if not pdf_links:
                    print("  No PDF links found among download buttons.")
                    continue

                for download_link in pdf_links:
                    # Clean filename
                    raw_filename = download_link.split("/")[-1].split("?")[0]
                    filename = requests.utils.unquote(raw_filename)
                    if not filename.lower().endswith(".pdf"):
                        filename += ".pdf"

                    # If multiple files exist for the same post, customize note title if needed
                    note_title = title
                    if len(pdf_links) > 1:
                        # Append a clean file identifier to disambiguate
                        stem = filename.replace(".pdf", "").replace("_", " ").strip()
                        if stem and stem.lower() not in title.lower():
                            note_title = f"{title} - {stem}"

                    # Check DB duplicate before downloading
                    if notes_collection.find_one({"fileName": filename, "title": note_title}):
                        print(f"  [Skipped] Already exists in MongoDB: {filename}")
                        continue

                    print(f"  Downloading PDF: {download_link}")
                    pdf_res = session.get(download_link, headers=HEADERS, timeout=60)
                    pdf_res.raise_for_status()
                    pdf_bytes = pdf_res.content

                    # Save locally
                    local_path = os.path.join(DOWNLOAD_DIR, filename)
                    with open(local_path, "wb") as f:
                        f.write(pdf_bytes)
                    print(f"  Saved locally to: {local_path}")

                    # Upload to MongoDB
                    upload_pdf_to_mongodb(
                        pdf_bytes=pdf_bytes,
                        filename=filename,
                        title=note_title,
                        description=meta["description"],
                        university=meta["university"],
                        course=meta["course"],
                        study_type=study_type,
                        year=meta["year"],
                        tags=tags,
                        uploader_id=uploader_user_id,
                    )

            except Exception as err:
                print(f"  [Error] Failed processing {material_url}: {err}")

        page_num += 1


if __name__ == "__main__":
    scrape_materials()
