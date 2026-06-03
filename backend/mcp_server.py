import re
import json
import httpx
from bs4 import BeautifulSoup
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("security-tools", host="127.0.0.1", port=3001)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
ATTACK_TAXII = (
    "https://attack.mitre.org/taxii/api/v21/collections/"
    "1f5ab827-3aba-4e41-be48-1e79f1df7e95/objects/"
)

ALLOWED_URLS = {
    # Security / threat intel
    "https://nvd.nist.gov",
    "https://www.cisa.gov",
    "https://attack.mitre.org",
    "https://www.cve.org",
    # Palo Alto Networks
    "https://unit42.paloaltonetworks.com",
    "https://docs.paloaltonetworks.com",
    "https://live.paloaltonetworks.com",
    "https://pan.dev",
    # CrowdStrike
    "https://www.crowdstrike.com",
    "https://developer.crowdstrike.com",
    # Zscaler
    "https://help.zscaler.com",
    "https://automate.zscaler.com",
    "https://www.zscaler.com",
    # Wiz
    "https://wiz.readthedocs.io",
    "https://www.wiz.io",
    # Microsoft
    "https://learn.microsoft.com",
    "https://microsoft.github.io",
    # Google AI
    "https://ai.google.dev",
}


def _is_allowed(url: str) -> bool:
    return any(url.startswith(prefix) for prefix in ALLOWED_URLS)


@mcp.tool()
async def lookup_cve(cve_id: str) -> str:
    """Look up detailed information about a specific CVE from the NVD database."""
    cve_id = cve_id.upper().strip()
    if not re.match(r"^CVE-\d{4}-\d+$", cve_id):
        return f"Invalid CVE ID '{cve_id}'. Expected format: CVE-YYYY-NNNNN"

    async with httpx.AsyncClient() as client:
        r = await client.get(f"{NVD_BASE}?cveId={cve_id}", timeout=10.0)
        r.raise_for_status()
        data = r.json()

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return f"{cve_id} not found in NVD."

    cve = vulns[0]["cve"]
    desc = next(
        (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
        "No description available.",
    )

    metrics = cve.get("metrics", {})
    cvss_score = severity = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m = metrics[key][0]
            cvss_score = m.get("cvssData", {}).get("baseScore")
            severity = m.get("baseSeverity") or m.get("cvssData", {}).get("baseSeverity")
            break

    published = cve.get("published", "")[:10]
    cwes = [
        w["description"][0]["value"]
        for w in cve.get("weaknesses", [])
        if w.get("description")
    ]

    lines = [f"**{cve_id}**", f"Published: {published}"]
    if cvss_score:
        lines.append(f"CVSS: {cvss_score} ({severity})")
    if cwes:
        lines.append(f"CWE: {', '.join(cwes[:3])}")
    lines += ["", desc]
    return "\n".join(lines)


@mcp.tool()
async def search_cves(keyword: str, limit: int = 5) -> str:
    """Search for CVEs by keyword (e.g. 'log4j', 'Apache', 'remote code execution')."""
    limit = min(limit, 10)
    async with httpx.AsyncClient() as client:
        r = await client.get(
            NVD_BASE,
            params={"keywordSearch": keyword, "resultsPerPage": limit},
            timeout=15.0,
        )
        r.raise_for_status()
        data = r.json()

    vulns = data.get("vulnerabilities", [])
    total = data.get("totalResults", 0)
    if not vulns:
        return f"No CVEs found for '{keyword}'."

    lines = [f"Found {total} CVEs for '{keyword}' (showing {len(vulns)}):"]
    for v in vulns:
        cve = v["cve"]
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
            "No description.",
        )
        short = desc[:120] + ("..." if len(desc) > 120 else "")

        metrics = cve.get("metrics", {})
        score = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                score = metrics[key][0].get("cvssData", {}).get("baseScore")
                break

        score_str = f" [CVSS {score}]" if score else ""
        lines.append(f"\n• {cve['id']}{score_str}\n  {short}")

    return "\n".join(lines)


@mcp.tool()
async def lookup_attack_technique(technique_id: str) -> str:
    """Look up a MITRE ATT&CK technique by ID (e.g. T1055, T1566.001)."""
    technique_id = technique_id.upper().strip()
    if not re.match(r"^T\d{4}(\.\d{3})?$", technique_id):
        return f"Invalid ATT&CK ID '{technique_id}'. Expected format: T1055 or T1055.001"

    async with httpx.AsyncClient() as client:
        r = await client.get(
            ATTACK_TAXII,
            params={
                "match[external_references.external_id]": technique_id,
                "match[type]": "attack-pattern",
            },
            headers={"Accept": "application/taxii+json;version=2.1"},
            timeout=15.0,
        )
        r.raise_for_status()
        data = r.json()

    objects = data.get("objects", [])
    if not objects:
        return f"ATT&CK technique {technique_id} not found."

    obj = objects[0]
    name = obj.get("name", "Unknown")
    desc = obj.get("description", "No description.")[:600]
    platforms = obj.get("x_mitre_platforms", [])
    detection = obj.get("x_mitre_detection", "")[:300]

    lines = [f"**{technique_id}: {name}**"]
    if platforms:
        lines.append(f"Platforms: {', '.join(platforms)}")
    lines += ["", desc]
    if detection:
        lines += ["", f"Detection: {detection}"]
    return "\n".join(lines)


@mcp.tool()
async def fetch_url(url: str) -> str:
    """Fetch content from an approved resource. Allowed domains: nvd.nist.gov, cisa.gov, attack.mitre.org, cve.org, paloaltonetworks.com (unit42/docs/live), pan.dev, crowdstrike.com, developer.crowdstrike.com, zscaler.com (help/automate/www), wiz.io, wiz.readthedocs.io, learn.microsoft.com, microsoft.github.io, ai.google.dev"""
    if not _is_allowed(url):
        allowed = "\n".join(f"  • {u}" for u in sorted(ALLOWED_URLS))
        return f"URL not permitted. Approved prefixes:\n{allowed}"

    async with httpx.AsyncClient() as client:
        r = await client.get(
            url,
            timeout=10.0,
            follow_redirects=True,
            headers={"User-Agent": "security-demo/1.0"},
        )
        r.raise_for_status()

    content_type = r.headers.get("content-type", "")
    if "json" in content_type:
        return r.text[:3000]

    soup = BeautifulSoup(r.text, "html.parser")
    for tag in soup(["script", "style", "nav", "footer", "header"]):
        tag.decompose()
    text = re.sub(r"\s+", " ", soup.get_text()).strip()
    return text[:3000]


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
