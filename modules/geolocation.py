import requests
import ipaddress

_GEO_CACHE = {}

def geolocate_ip(ip_address: str) -> dict:
    """
    Geolocates a public IP address using the ip-api.com service.
    Validates IP, checks cache, and handles API errors gracefully.
    """
    result = {
        "available": False,
        "source": "ip-api",
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
        if ip.is_private or ip.is_reserved or ip.is_loopback or \
           ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            result["error"] = "IP is private, reserved, or non-routable."
            return result
    except ValueError:
        result["error"] = "Invalid IP address."
        return result

    # 2. Check cache
    if ip_address in _GEO_CACHE:
        return _GEO_CACHE[ip_address]

    # 3. Call API
    url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,proxy,hosting,query"
    
    try:
        response = requests.get(url, timeout=5.0)
        
        # Read Rate limit headers
        rl = response.headers.get("X-Rl")
        ttl = response.headers.get("X-Ttl")
        if rl is not None:
            result["rate_limit_remaining"] = int(rl)
        if ttl is not None:
            result["rate_limit_reset_seconds"] = int(ttl)

        if response.status_code == 429:
            result["error"] = "Rate limit exceeded (HTTP 429)."
            return result

        response.raise_for_status()
        data = response.json()

        if data.get("status") == "fail":
            result["error"] = f"API error: {data.get('message', 'Unknown error')}"
        else:
            result["available"] = True
            result["proxy"] = data.get("proxy", False)
            result["hosting"] = data.get("hosting", False)
            result["location"] = {
                "country": data.get("country"),
                "countryCode": data.get("countryCode"),
                "regionName": data.get("regionName"),
                "city": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "timezone": data.get("timezone"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "as": data.get("as")
            }
            
            # Cache the successful result
            _GEO_CACHE[ip_address] = result

    except requests.exceptions.Timeout:
        result["error"] = "Request timed out."
    except requests.exceptions.RequestException as e:
        result["error"] = f"Request failed: {str(e)}"
    except ValueError:
        result["error"] = "Invalid JSON response from API."
    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"

    return result
