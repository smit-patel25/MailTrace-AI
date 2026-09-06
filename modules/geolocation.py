import requests
import ipaddress
import json

def geolocate_ip(ip_address: str) -> dict:
    """
    Geolocates a public IP address using the freeipapi.com service.
    Validates IP locally, rejects non-global IPs without any external request.
    """
    result = {
        "available": False,
        "source": "freeipapi",
        "error": None,
        "location": {},
        "proxy": False,
        "hosting": False,
        "rate_limit_remaining": None,
        "rate_limit_reset_seconds": None
    }

    # 1. Validation and early rejection
    try:
        ip = ipaddress.ip_address(ip_address)
        # Check against private, reserved, loopback, link-local, multicast, unspecified
        if ip.is_private or ip.is_reserved or ip.is_loopback or \
           ip.is_link_local or ip.is_multicast or ip.is_unspecified or not ip.is_global:
            result["error"] = "IP is private, reserved, or non-routable."
            return result
        # Extract canonical string representation
        canonical_ip = str(ip)
    except ValueError:
        result["error"] = "Invalid IP address."
        return result

    # 2. Call API
    url = f"https://free.freeipapi.com/api/json/{canonical_ip}"

    try:
        # TLS verification enabled, no redirects, strict timeouts
        # Stream=True to enforce size limit before parsing
        with requests.get(url, timeout=(3.0, 5.0), allow_redirects=False, stream=True) as response:
            if response.status_code == 429:
                result["error"] = "Rate limit exceeded (HTTP 429)."
                return result

            if response.status_code != 200:
                result["error"] = "API error: Unexpected HTTP status."
                return result

            # Read safely up to 8KB to avoid decompression bombs / large payloads
            raw_data = response.raw.read(8192)
            if not raw_data:
                result["error"] = "Empty response from API."
                return result

            # Attempt to decode JSON
            try:
                data = json.loads(raw_data.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                result["error"] = "Invalid JSON response from API."
                return result

        # 3. Defensive extraction and schema mapping
        if not isinstance(data, dict):
            result["error"] = "Invalid JSON schema."
            return result

        result["available"] = True
        result["proxy"] = bool(data.get("isProxy", False))
        # FreeIPAPI does not provide hosting status reliably. Do not double count.
        result["hosting"] = False

        # Extract coordinates, validating types
        lat = data.get("latitude")
        lon = data.get("longitude")

        # Enforce range limits and float types
        valid_lat, valid_lon = None, None
        try:
            if lat is not None:
                parsed_lat = float(lat)
                if -90.0 <= parsed_lat <= 90.0:
                    valid_lat = parsed_lat
            if lon is not None:
                parsed_lon = float(lon)
                if -180.0 <= parsed_lon <= 180.0:
                    valid_lon = parsed_lon
        except (ValueError, TypeError):
            pass

        result["location"] = {
            "country": str(data.get("countryName", "")) if data.get("countryName") else None,
            "countryCode": str(data.get("countryCode", "")) if data.get("countryCode") else None,
            "regionName": str(data.get("regionName", "")) if data.get("regionName") else None,
            "city": str(data.get("cityName", "")) if data.get("cityName") else None,
            "lat": valid_lat,
            "lon": valid_lon,
            "timezone": None, # freeipapi doesn't provide this in standard endpoint reliably
            "isp": None,      # freeipapi doesn't provide ISP separately
            "org": str(data.get("asnOrganization", "")) if data.get("asnOrganization") else None,
            "as": str(data.get("asn", "")) if data.get("asn") else None
        }

    except requests.exceptions.Timeout:
        result["error"] = "Request timed out."
    except requests.exceptions.RequestException:
        # Don't leak exact exceptions strings to UI (e.g., DNS failures, SSLErrors)
        result["error"] = "Request failed."
    except Exception:
        # Catch-all
        result["error"] = "Unexpected error."

    return result
