"""
Real-World Threat Intelligence Integration: CISA KEV Catalog Fetcher
Connects to the official US Cybersecurity & Infrastructure Security Agency (CISA)
Known Exploited Vulnerabilities (KEV) Catalog public feed.

Downloads real, actively exploited CVEs and maps them to host software inventory.
"""

import os
import json
import urllib.request
import logging
from typing import List, Dict, Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("CISAKEVFetcher")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

class CISAKEVFetcher:
    def __init__(self, raw_data_dir: str):
        self.raw_data_dir = raw_data_dir
        self.kev_file_path = os.path.join(raw_data_dir, "cisa_known_exploited_vulnerabilities.json")

    def download_cisa_catalog(self) -> Dict[str, Any]:
        """Downloads the official CISA KEV catalog JSON feed."""
        logger.info(f"Connecting to official CISA KEV feed: {CISA_KEV_URL}")
        req = urllib.request.Request(
            CISA_KEV_URL,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AI-CSPM-Scanner/1.0"}
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                raw_json = response.read().decode("utf-8")
                catalog_data = json.loads(raw_json)
                
                os.makedirs(self.raw_data_dir, exist_ok=True)
                with open(self.kev_file_path, "w", encoding="utf-8") as f:
                    json.dump(catalog_data, f, indent=2)
                
                version = catalog_data.get("catalogVersion", "Unknown")
                count = catalog_data.get("count", len(catalog_data.get("vulnerabilities", [])))
                logger.info(f"Successfully downloaded CISA KEV Catalog (Version {version}) containing {count} active vulnerabilities.")
                return catalog_data
        except Exception as e:
            logger.warning(f"Unable to fetch live CISA feed ({e}). Checking local cache...")
            if os.path.exists(self.kev_file_path):
                with open(self.kev_file_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            raise

    def get_cloud_relevant_cves(self, limit: int = 40) -> List[Dict[str, Any]]:
        """Filters catalog for common cloud, operating system, and web server vulnerabilities."""
        if not os.path.exists(self.kev_file_path):
            catalog = self.download_cisa_catalog()
        else:
            with open(self.kev_file_path, "r", encoding="utf-8") as f:
                catalog = json.load(f)

        vulnerabilities = catalog.get("vulnerabilities", [])
        
        # Priority enterprise/cloud software keywords
        cloud_keywords = [
            "apache", "openssh", "nginx", "log4j", "linux", "sudo",
            "microsoft", "windows", "docker", "openssl", "curl", "redis"
        ]

        relevant = []
        for v in vulnerabilities:
            name_lower = v.get("vulnerabilityName", "").lower()
            product_lower = v.get("product", "").lower()
            vendor_lower = v.get("vendorProject", "").lower()

            text_block = f"{name_lower} {product_lower} {vendor_lower}"
            if any(k in text_block for k in cloud_keywords):
                relevant.append({
                    "cve_id": v.get("cveID"),
                    "vendor": v.get("vendorProject"),
                    "product": v.get("product"),
                    "vulnerability_name": v.get("vulnerabilityName"),
                    "date_added_to_cisa": v.get("dateAdded"),
                    "required_action": v.get("requiredAction"),
                    "cisa_known_exploited": True,
                    "short_description": v.get("shortDescription")
                })
                if len(relevant) >= limit:
                    break

        return relevant

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    raw_dir = os.path.join(base_dir, "data", "raw")
    fetcher = CISAKEVFetcher(raw_dir)
    data = fetcher.download_cisa_catalog()
    sample = fetcher.get_cloud_relevant_cves(limit=5)
    print(f"Loaded {len(sample)} sample cloud-relevant CISA vulnerabilities:")
    for s in sample:
        print(f" - {s['cve_id']} ({s['product']}): {s['vulnerability_name']}")
