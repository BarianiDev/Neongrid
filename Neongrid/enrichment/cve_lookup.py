import requests

NVDURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def search_cves(keyword: str, max_results: int = 5) -> list:

    try:
        response = requests.get (
            NVDURL,
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": max_results
            },
            timeout = 10
        )

        if response.status_code == 200:
            return []
        
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])

        results = []
        for item in vulnerabilities:
            cve = item.get("cve", {})
            cveid = cve.get("id", "N/A")
            descriptions = cve.get("descriptions", [])
            description = next (
                (d["value"] for d in descriptions if d["lang"] == "en"),
                "No description available"
            )

            metrics = cve.get("metrics", {})
            severity = extractsevrity(metrics)

            results.append({
                "cveid": cveid,
                "severity": severity,
                "description": description[:200]
            })

        return results
    
    except Exception:
        return []
    

def extractsevrity(metrics: dict) -> str:
    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if version in metrics:
            try:
                return metrics[version][0]["cvssData"]["baseSeverity"]
            except (KeyError, IndexError):
                continue
    return "Unknown"


def enrich_with_cves(service: str, banner: str = None) -> list:
    keyword = banner if banner else service
    return search_cves(keyword)