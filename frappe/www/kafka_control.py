#!/usr/bin/env python3
"""
Scrape Head of Department (HOD) name, email, and department from iitg.ac.in.

Discovers department/school/centre slugs from the academic dropdown on the
homepage, then visits each department listing page
(iitg_academic?aca=<slug>) and pulls out the "Head of the Department" card,
which looks like:

    <div class="col-md-8"><h4><a href="iitg_faculty_details.php?fac=...">
    <b>Uday&nbsp; S. Dixit</b></a></h4>
    <p>Professor,<br>Department of Mechanical Engineering</p>
    <i class="fa fa-envelope"></i>&nbsp; hociks @ iitg.ac.in</div>

Standalone script -- uses only the Python standard library (urllib + re),
no pip install needed. This is separate from iitg_faculty_scraper.py, which
scrapes the full faculty roster.

Usage:
    python3 iitg_department_heads_scraper.py
    python3 iitg_department_heads_scraper.py --departments mechanical-engineering,chemistry
    python3 iitg_department_heads_scraper.py --output heads.csv
"""

import argparse
import csv
import html
import re
import sys
import time
import urllib.error
import urllib.request

BASE_URL = "https://iitg.ac.in/"
HOME_URL = BASE_URL
DEPT_URL_TMPL = BASE_URL + "iitg_academic?aca={slug}"
FACULTY_URL_TMPL = BASE_URL + "iitg_faculty_details.php?fac={fac_id}"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    )
}

DEPT_SLUG_RE = re.compile(r'iitg_academic\?aca=([a-z0-9\-]+)', re.I)
DEPT_TITLE_RE = re.compile(r'<h2 class="text-white font-32 mb-0">(.*?)</h2>', re.S)

HOD_BLOCK_RE = re.compile(
    r'<div class="col-md-8"><h4><a href="iitg_faculty_details\.php\?fac=([^"]+)"'
    r' class="text-danger"><b>(.*?)</b></a></h4>(.*?)</div>',
    re.S,
)
HOD_EMAIL_RE = re.compile(r'fa-envelope"></i>\s*(?:&nbsp;)?\s*([^\r\n<]+)')
DESIGNATION_RE = re.compile(r'^\s*([^,]+),')
PHONE_RE = re.compile(r'Ph(?:one)?[:.]?\s*([\d\-+,()\s]{6,})', re.I)


def classify_section(slug):
    """Classify a department/school/centre slug into 'School', 'Centre', or 'Department'."""
    s = slug.lower()
    if 'school' in s:
        return "School"
    if 'centre' in s or 'center' in s:
        return "Centre"
    return "Department"


def clean_text(text):
    text = html.unescape(text)
    text = re.sub(r'<[^>]+>', ' ', text)
    return ' '.join(text.split())


def normalize_email(raw):
    if not raw:
        return ""
    email = clean_text(raw)
    email = email.replace('⋅', '.').replace('[AT]', '@').replace('[DOT]', '.')
    email = email.replace(' ', '')
    return email.lower()


def fetch(url, retries=3, timeout=15, backoff=1.5):
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                charset = resp.headers.get_content_charset() or "utf-8"
                return resp.read().decode(charset, errors="replace")
        except (urllib.error.URLError, TimeoutError) as e:
            last_err = e
            time.sleep(backoff * attempt)
    print(f"  ! failed to fetch {url}: {last_err}", file=sys.stderr)
    return None


def discover_department_slugs():
    page = fetch(HOME_URL)
    if not page:
        return []
    slugs = []
    seen = set()
    for slug in DEPT_SLUG_RE.findall(page):
        if slug not in seen:
            seen.add(slug)
            slugs.append(slug)
    return slugs


def parse_department_head(page):
    """Returns dict with dept_title, fac_id, name, designation, phone, email -- or None if no HOD block found."""
    title_m = DEPT_TITLE_RE.search(page)
    dept_title = clean_text(title_m.group(1)) if title_m else ""

    hod_m = HOD_BLOCK_RE.search(page)
    if not hod_m:
        return None

    fac_id, name, rest = hod_m.groups()

    email_m = HOD_EMAIL_RE.search(rest)
    email = normalize_email(email_m.group(1)) if email_m else ""

    body_text = clean_text(rest)
    if email:
        body_text = body_text.replace(email_m.group(1).strip(), "").strip()
        body_text = clean_text(body_text)

    desig_m = DESIGNATION_RE.search(body_text)
    designation = desig_m.group(1).strip() if desig_m else ""

    phone_m = PHONE_RE.search(body_text)
    phone = phone_m.group(1).strip().rstrip(',') if phone_m else ""

    return {
        "department": dept_title,
        "fac_id": fac_id,
        "name": clean_text(name),
        "designation": designation,
        "phone": phone,
        "email": email,
    }


def collect_department_heads(slugs, on_progress=None):
    heads = []
    total = len(slugs)
    for i, slug in enumerate(slugs):
        url = DEPT_URL_TMPL.format(slug=slug)
        print(f"[dept] {slug}")
        page = fetch(url)
        if page:
            head = parse_department_head(page)
            if head:
                head["slug"] = slug
                head["section"] = classify_section(slug)
                heads.append(head)
            else:
                print(f"  ! no Head of Department block found on {slug}", file=sys.stderr)
        if on_progress:
            on_progress(i + 1, total)
    return heads


def write_csv(heads, output_path):
    heads_sorted = sorted(heads, key=lambda h: (h["section"], h["department"]))
    fieldnames = ["Section", "Department", "Name", "Email", "Designation", "Phone", "Profile URL"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for h in heads_sorted:
            writer.writerow({
                "Section": h["section"],
                "Department": h["department"],
                "Name": h["name"],
                "Email": h["email"],
                "Designation": h["designation"],
                "Phone": h["phone"],
                "Profile URL": FACULTY_URL_TMPL.format(fac_id=h["fac_id"]),
            })


def main():
    parser = argparse.ArgumentParser(description="Scrape IITG Head of Department name/email/department.")
    parser.add_argument("--departments", help="Comma-separated list of department slugs to scrape "
                                                "(default: auto-discover all from the homepage dropdown)")
    parser.add_argument("--output", default="iitg_department_heads.csv", help="Output CSV path")
    args = parser.parse_args()

    if args.departments:
        slugs = [s.strip() for s in args.departments.split(",") if s.strip()]
    else:
        print("[discover] finding department slugs from academic dropdown ...")
        slugs = discover_department_slugs()
        print(f"[discover] found {len(slugs)} departments: {', '.join(slugs)}")

    if not slugs:
        print("No department slugs found/given. Exiting.", file=sys.stderr)
        sys.exit(1)

    heads = collect_department_heads(slugs)
    write_csv(heads, args.output)

    with_email = sum(1 for h in heads if h["email"])
    print(f"\nWrote {len(heads)} department heads to {args.output} ({with_email} with an email address).")


if __name__ == "__main__":
    main()




#!/usr/bin/env python3
"""
Scrape faculty name, email, and department from iitg.ac.in.

Two-pass approach:
  1. Discover department slugs from the academic dropdown on the homepage,
     then visit each department listing page (iitg_academic?aca=<slug>) to
     collect every faculty member's name and profile id ("fac").
  2. Visit each faculty member's own profile page
     (iitg_faculty_details.php?fac=<id>) to get their authoritative name,
     designation, department/centre affiliation(s), and email.

     Emails on iitg.ac.in are lightly obfuscated against scraping: dots are
     rendered as the unicode dot operator "⋅" (e.g. "name @ iitg ⋅ ac ⋅ in").
     This script normalizes that back to a real address.

Uses only the Python standard library (urllib + re) -- no pip install needed.

Usage:
    python3 iitg_faculty_scraper.py
    python3 iitg_faculty_scraper.py --departments mechanical-engineering,chemistry
    python3 iitg_faculty_scraper.py --output faculty.csv --workers 8
"""

import argparse
import csv
import html
import re
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_URL = "https://iitg.ac.in/"
HOME_URL = BASE_URL
DEPT_URL_TMPL = BASE_URL + "iitg_academic?aca={slug}"
FACULTY_URL_TMPL = BASE_URL + "iitg_faculty_details.php?fac={fac_id}"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    )
}

DEPT_SLUG_RE = re.compile(r'iitg_academic\?aca=([a-z0-9\-]+)', re.I)
DEPT_TITLE_RE = re.compile(r'<h2 class="text-white font-32 mb-0">(.*?)</h2>', re.S)

HOD_BLOCK_RE = re.compile(
    r'<div class="col-md-8"><h4><a href="iitg_faculty_details\.php\?fac=([^"]+)"'
    r' class="text-danger"><b>(.*?)</b></a></h4>(.*?)</div>',
    re.S,
)
HOD_EMAIL_RE = re.compile(r'fa-envelope"></i>\s*(?:&nbsp;)?\s*([^\r\n<]+)')

GRID_ENTRY_RE = re.compile(
    r'<a href="iitg_faculty_details\.php\?name=[^&"]+&fac=([^"]+)"'
    r' class="text-ddanger"><b>(.*?)</b><br>([^<]*)</a>',
    re.S,
)

DETAIL_NAME_RE = re.compile(r'<h3 class="name font-30 mt-0 mb-0">(.*?)</h3>', re.S)
DETAIL_DESIG_RE = re.compile(r'<h4 class="mt-5">(.*?)</h4>', re.S)
DETAIL_EMAIL_RE = re.compile(r'fa-envelope-o"></i>.*?<span class="text-info">(.*?)</span>', re.S)
DETAIL_DEPTS_RE = re.compile(r'Department/Centre/School</h3>(.*?)</div>\s*</div>', re.S)
DEPT_TAG_RE = re.compile(r'<a href="iitg_academic\.php\?aca=[^"]+">([^<]+)</a>')


def classify_section(slug):
    """Classify a department/school/centre slug into 'School', 'Centre', or 'Department'."""
    s = slug.lower()
    if 'school' in s:
        return "School"
    if 'centre' in s or 'center' in s:
        return "Centre"
    return "Department"


def clean_text(text):
    text = html.unescape(text)
    text = re.sub(r'<[^>]+>', ' ', text)
    return ' '.join(text.split())


def normalize_email(raw):
    if not raw:
        return ""
    email = clean_text(raw)
    email = email.replace('⋅', '.').replace('[AT]', '@').replace('[DOT]', '.')
    email = email.replace(' ', '')
    return email.lower()


def fetch(url, retries=3, timeout=15, backoff=1.5):
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                charset = resp.headers.get_content_charset() or "utf-8"
                return resp.read().decode(charset, errors="replace")
        except (urllib.error.URLError, TimeoutError) as e:
            last_err = e
            time.sleep(backoff * attempt)
    print(f"  ! failed to fetch {url}: {last_err}", file=sys.stderr)
    return None


def discover_department_slugs():
    page = fetch(HOME_URL)
    if not page:
        return []
    slugs = []
    seen = set()
    for slug in DEPT_SLUG_RE.findall(page):
        if slug not in seen:
            seen.add(slug)
            slugs.append(slug)
    return slugs


def parse_department_page(page):
    """Returns (dept_title, {fac_id: {...}}, hod_fac_id_or_None)"""
    title_m = DEPT_TITLE_RE.search(page)
    dept_title = clean_text(title_m.group(1)) if title_m else ""

    people = {}
    hod_fac_id = None

    hod_m = HOD_BLOCK_RE.search(page)
    if hod_m:
        fac_id, name, rest = hod_m.groups()
        hod_fac_id = fac_id
        email_m = HOD_EMAIL_RE.search(rest)
        people[fac_id] = {
            "name": clean_text(name),
            "designation": "",
            "department": dept_title,
            "email": normalize_email(email_m.group(1)) if email_m else "",
        }

    for fac_id, name, designation in GRID_ENTRY_RE.findall(page):
        entry = people.setdefault(fac_id, {"name": "", "designation": "", "department": dept_title, "email": ""})
        entry["name"] = clean_text(name)
        entry["designation"] = clean_text(designation)
        entry["department"] = dept_title

    return dept_title, people, hod_fac_id


def parse_faculty_detail(page):
    name_m = DETAIL_NAME_RE.search(page)
    desig_m = DETAIL_DESIG_RE.search(page)
    email_m = DETAIL_EMAIL_RE.search(page)
    depts_m = DETAIL_DEPTS_RE.search(page)

    departments = []
    if depts_m:
        departments = [clean_text(d) for d in DEPT_TAG_RE.findall(depts_m.group(1))]

    return {
        "name": clean_text(name_m.group(1)) if name_m else "",
        "designation": clean_text(desig_m.group(1)) if desig_m else "",
        "email": normalize_email(email_m.group(1)) if email_m else "",
        "departments": departments,
    }


def collect_faculty_from_departments(slugs, on_progress=None):
    """Returns dict: fac_id -> {'name', 'designation', 'department', 'section', 'email', 'source_slugs': set}"""
    all_faculty = {}
    total = len(slugs)
    for i, slug in enumerate(slugs):
        url = DEPT_URL_TMPL.format(slug=slug)
        print(f"[dept] {slug}")
        page = fetch(url)
        if page:
            dept_title, people, _hod_fac_id = parse_department_page(page)
            section = classify_section(slug)
            for fac_id, info in people.items():
                record = all_faculty.setdefault(fac_id, {
                    "name": info["name"],
                    "designation": info["designation"],
                    "department": info["department"],
                    "section": section,
                    "email": info["email"],
                    "source_slugs": set(),
                })
                if not record["name"]:
                    record["name"] = info["name"]
                if not record["designation"]:
                    record["designation"] = info["designation"]
                if not record["email"]:
                    record["email"] = info["email"]
                record["source_slugs"].add(slug)
        if on_progress:
            on_progress(i + 1, total)
    return all_faculty


def enrich_with_profile_pages(all_faculty, workers=6, delay=0.0, on_progress=None):
    fac_ids = list(all_faculty.keys())
    print(f"\n[profiles] fetching {len(fac_ids)} faculty profile pages with {workers} workers ...")

    def worker(fac_id):
        url = FACULTY_URL_TMPL.format(fac_id=fac_id)
        page = fetch(url)
        if delay:
            time.sleep(delay)
        if not page:
            return fac_id, None
        return fac_id, parse_faculty_detail(page)

    done = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(worker, fac_id): fac_id for fac_id in fac_ids}
        for fut in as_completed(futures):
            fac_id, detail = fut.result()
            done += 1
            if done % 25 == 0 or done == len(fac_ids):
                print(f"  ... {done}/{len(fac_ids)}")
            if on_progress:
                on_progress(done, len(fac_ids))
            if not detail:
                continue
            record = all_faculty[fac_id]
            if detail["name"]:
                record["name"] = detail["name"]
            if detail["designation"]:
                record["designation"] = detail["designation"]
            if detail["email"]:
                record["email"] = detail["email"]
            if detail["departments"]:
                record["department"] = "; ".join(detail["departments"])
                record["section"] = "; ".join(classify_section(d) for d in detail["departments"])


def write_csv(all_faculty, output_path):
    rows = []
    for fac_id, r in all_faculty.items():
        rows.append({
            "Name": r["name"],
            "Email": r["email"],
            "Section": r["section"],
            "Department": r["department"],
            "Designation": r["designation"],
            "Profile URL": FACULTY_URL_TMPL.format(fac_id=fac_id),
        })
    rows.sort(key=lambda r: (r["Section"], r["Department"], r["Name"]))

    fieldnames = ["Name", "Email", "Section", "Department", "Designation", "Profile URL"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    return rows


def main():
    parser = argparse.ArgumentParser(description="Scrape IITG faculty name/email/department.")
    parser.add_argument("--departments", help="Comma-separated list of department slugs to scrape "
                                                "(default: auto-discover all from the homepage dropdown)")
    parser.add_argument("--output", default="iitg_faculty.csv", help="Output CSV path")
    parser.add_argument("--workers", type=int, default=6, help="Concurrent workers for profile-page fetches")
    parser.add_argument("--delay", type=float, default=0.0, help="Extra delay (seconds) per profile-page request")
    args = parser.parse_args()

    if args.departments:
        slugs = [s.strip() for s in args.departments.split(",") if s.strip()]
    else:
        print("[discover] finding department slugs from academic dropdown ...")
        slugs = discover_department_slugs()
        print(f"[discover] found {len(slugs)} departments: {', '.join(slugs)}")

    if not slugs:
        print("No department slugs found/given. Exiting.", file=sys.stderr)
        sys.exit(1)

    all_faculty = collect_faculty_from_departments(slugs)
    print(f"\n[collect] found {len(all_faculty)} unique faculty across {len(slugs)} department page(s)")

    enrich_with_profile_pages(all_faculty, workers=args.workers, delay=args.delay)

    rows = write_csv(all_faculty, args.output)
    with_email = sum(1 for r in rows if r["Email"])
    print(f"\nWrote {len(rows)} rows to {args.output} ({with_email} with an email address).")


if __name__ == "__main__":
    main()
