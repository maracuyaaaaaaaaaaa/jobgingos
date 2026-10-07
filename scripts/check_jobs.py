#!/usr/bin/env python3
"""Re-verifica las ofertas y portales clave directamente en el ATS de cada empresa.

Uso:  python3 scripts/check_jobs.py
Solo usa la biblioteca estándar. Imprime, por fuente, los puestos cuyo título
coincide con palabras clave de malware / CTI / detección / pentest, para que
puedas comparar con la tabla de docs/investigacion-empleo-2026-10.md.
"""
import json
import re
import urllib.request

UA = {"User-Agent": "Mozilla/5.0 (job-check script)", "Accept": "application/json"}
KW = re.compile(
    r"malware|revers|threat|intel|detect|hunt|\bsoc\b|incident|dfir|forensic|"
    r"research|penetration|pentest|red team|offensive|\bcti\b|security (engineer|analyst)",
    re.I,
)


def fetch(url, data=None, headers=None):
    req = urllib.request.Request(url, data=data, headers={**UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "replace")


def greenhouse(board):
    d = json.loads(fetch(f"https://boards-api.greenhouse.io/v1/boards/{board}/jobs"))
    return [(j["title"], j["location"]["name"], j["absolute_url"]) for j in d["jobs"]]


def lever(company):
    d = json.loads(fetch(f"https://api.lever.co/v0/postings/{company}?mode=json"))
    return [(j["text"], j.get("categories", {}).get("location", ""), j["hostedUrl"]) for j in d]


def ashby(board):
    d = json.loads(fetch(f"https://api.ashbyhq.com/posting-api/job-board/{board}"))
    return [(j["title"], j.get("location", ""), j["jobUrl"]) for j in d["jobs"]]


def bamboohr(company):
    d = json.loads(fetch(f"https://{company}.bamboohr.com/careers/list"))
    return [
        (j["jobOpeningName"], j.get("employmentStatusLabel", ""),
         f"https://{company}.bamboohr.com/careers/{j['id']}")
        for j in d["result"]
    ]


def workday(host, tenant, site, query):
    body = json.dumps({"appliedFacets": {}, "limit": 20, "offset": 0, "searchText": query}).encode()
    d = json.loads(fetch(f"https://{host}/wday/cxs/{tenant}/{site}/jobs", data=body,
                         headers={"Content-Type": "application/json"}))
    return [(j["title"], j.get("locationsText", ""), f"https://{host}/{site}{j['externalPath']}")
            for j in d.get("jobPostings", [])]


def wazuh():
    # The slug does not always match the title (the Detection Engineer posting
    # lives at /job/senior-software-engineer-cti/), so read each page's <title>.
    html = fetch("https://wazuh.com/careers/")
    slugs = sorted(set(re.findall(r"https://wazuh\.com/job/([a-z0-9-]+)/", html)))
    rows = []
    for s in slugs:
        url = f"https://wazuh.com/job/{s}/"
        m = re.search(r"<title>(.*?)</title>", fetch(url), re.S)
        title = m.group(1).split("|")[0].strip() if m else s
        rows.append((title, "Remote", url))
    return rows


SOURCES = [
    ("Group-IB (Greenhouse)", lambda: greenhouse("groupib"), True),
    ("Intel 471 (BambooHR)", lambda: bamboohr("intel471"), False),
    ("Wazuh (careers page)", wazuh, True),
    ("CrowdStrike: 'LATAM'", lambda: workday("crowdstrike.wd5.myworkdayjobs.com", "crowdstrike", "crowdstrikecareers", "LATAM"), False),
    ("CrowdStrike: 'Colombia'", lambda: workday("crowdstrike.wd5.myworkdayjobs.com", "crowdstrike", "crowdstrikecareers", "Colombia"), False),
    ("Huntress (Greenhouse)", lambda: greenhouse("huntress"), True),
    ("Recorded Future (Greenhouse)", lambda: greenhouse("recordedfuture"), True),
    ("Sophos (Lever)", lambda: lever("sophos"), True),
    ("Flashpoint (Ashby)", lambda: ashby("flashpoint.io"), True),
    ("Canonical (Greenhouse)", lambda: greenhouse("canonical"), True),
    ("Clara (Greenhouse)", lambda: greenhouse("clara"), True),
    ("Bugcrowd (Greenhouse)", lambda: greenhouse("bugcrowd"), True),
]

if __name__ == "__main__":
    for name, fn, filter_kw in SOURCES:
        print(f"\n== {name}")
        try:
            rows = fn()
        except Exception as e:  # una fuente caída no debe detener las demás
            print(f"   ERROR: {e}")
            continue
        hits = [r for r in rows if not filter_kw or KW.search(r[0])]
        print(f"   {len(rows)} puestos en total, {len(hits)} relevantes")
        for title, loc, url in hits:
            print(f"   - {title} | {loc} | {url}")
