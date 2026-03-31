import requests
import json
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin
from .exceptions import APIError, RateLimitExceeded, ConfigurationError

class AsnApiClient:
    """
    Client for interacting with the ASN Intelligence API.
    """
    
    def __init__(self, base_url: str, api_key: str):
        if not base_url:
            raise ConfigurationError("base_url must be provided")
        if not api_key:
            raise ConfigurationError("api_key must be provided")
            
        self.base_url = base_url if base_url.endswith("/") else base_url + "/"
        self.api_key = api_key
        
        self.session = requests.Session()
        self.session.headers.update({
            "x-api-key": self.api_key,
            "Accept": "application/json",
            "User-Agent": "asn-api-python-sdk/1.0.0"
        })

    def _request(self, method: str, path: str, **kwargs) -> Any:
        url = urljoin(self.base_url, path)
        try:
            response = self.session.request(method, url, **kwargs)
            
            if response.status_code == 429:
                raise RateLimitExceeded("Rate limit exceeded. Please try again later.")
                
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.HTTPError as e:
            if getattr(e, 'response', None) is not None:
                try:
                    error_data = e.response.json()
                    detail = error_data.get("detail", str(e))
                except ValueError:
                    detail = e.response.text or str(e)
                raise APIError(f"HTTP {e.response.status_code}: {detail}", status_code=e.response.status_code)
            raise APIError(str(e))
        except requests.exceptions.RequestException as e:
            raise APIError(f"Request failed: {str(e)}")

    def get_score(self, asn: int) -> Dict[str, Any]:
        """Get risk score and details for a specific ASN."""
        return self._request("GET", f"v3/asn/{asn}")

    def get_history(self, asn: int, limit: int = 10, offset: int = 0) -> Dict[str, Any]:
        """Get scoring history for a specific ASN."""
        params = {"limit": limit, "offset": offset}
        return self._request("GET", f"v3/asn/{asn}/history", params=params)

    def bulk_check(self, asns: List[int]) -> Dict[str, Any]:
        """Perform a risk check on multiple ASNs simultaneously."""
        return self._request("POST", "v1/tools/bulk-risk-check", json={"asns": asns})

    def compare(self, asn_a: int, asn_b: int) -> Dict[str, Any]:
        """Compare two ASNs side-by-side to understand relative risk profiles."""
        params = {"asn_a": asn_a, "asn_b": asn_b}
        return self._request("GET", "v1/tools/compare", params=params)

    def get_peeringdb(self, asn: int) -> Dict[str, Any]:
        """Fetch PeeringDB metadata (ASN type, IXP count, facilities) for a specific ASN."""
        return self._request("GET", f"v1/asn/{asn}/peeringdb")

    def get_domain_risk(self, domain: str) -> Dict[str, Any]:
        """Analyze a domain finding its hosting IP and the underlying ASN risk score."""
        return self._request("GET", "v1/tools/domain-risk", params={"domain": domain})

    def get_edl(self, max_score: float = 50.0) -> str:
        """Get an External Dynamic List (EDL) of malicious ASNs for firewalls in plain text."""
        params = {"max_score": max_score}
        url = urljoin(self.base_url, "feeds/edl")
        
        try:
            response = self.session.request("GET", url, params=params)
            
            if response.status_code == 429:
                raise RateLimitExceeded("Rate limit exceeded. Please try again later.")
                
            response.raise_for_status()
            return response.text
            
        except requests.exceptions.HTTPError as e:
            if getattr(e, 'response', None) is not None:
                try:
                    error_data = e.response.json()
                    detail = error_data.get("detail", str(e))
                except ValueError:
                    detail = e.response.text or str(e)
                raise APIError(f"HTTP {e.response.status_code}: {detail}", status_code=e.response.status_code)
            raise APIError(str(e))
        except requests.exceptions.RequestException as e:
            raise APIError(f"Request failed: {str(e)}")

    def get_health(self) -> Dict[str, Any]:
        """Check API health and status."""
        return self._request("GET", "health")

    def close(self):
        """Close the underlying session."""
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

