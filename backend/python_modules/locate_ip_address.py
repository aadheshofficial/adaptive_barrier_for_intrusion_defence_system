import requests
import json

def get_geolocation(ip_address: str) -> dict:
    """
    Fetches geolocation details for a given IP address using ipinfo.io.

    Args:
        ip_address (str): The IP address to look up.

    Returns:
        dict: A JSON-compatible dictionary containing location details such as city, region, country, ISP, latitude, and longitude.
    """
    api_url = f"https://ipinfo.io/{ip_address}/json"
    
    try:
        response = requests.get(api_url, timeout=5)
        response.raise_for_status() 
        data = response.json()
        
        lat, lon = data.get("loc", "N/A,N/A").split(",")

        location: dict = {
            "ip": data.get("ip", "N/A"),
            "city": data.get("city", "N/A"),
            "region": data.get("region", "N/A"),
            "country": data.get("country", "N/A"),
            "latitude": lat,
            "longitude": lon,
            "isp": data.get("org", "N/A"),
        }
        return location

    except requests.exceptions.Timeout:
        return {"Error": "Request timed out. Please try again."}

    except requests.exceptions.ConnectionError:
        return {"Error": "Unable to connect to the geolocation service."}

    except requests.exceptions.HTTPError as http_err:
        return {"Error": f"HTTP Error: {http_err}"}

    except requests.exceptions.RequestException as e:
        return {"Error": f"Unexpected Error: {e}"}


def help()->None:
    """
    Provides detailed instructions on how to use the get_geolocation function.

    This function fetches geolocation details for a given IP address using ipinfo.io.
    
    Example:
        get_geolocation("8.8.8.8")

    This will return a JSON-formatted dictionary containing details such as city, region, country, latitude, longitude, and ISP.

    Returns:
        None
    """
    help_text = (
        "\nUsage:\n"
        "    Call the function get_geolocation(ip_address) with a valid IP address.\n"
        "    Example:\n"
        "        get_geolocation(\"8.8.8.8\")\n"
        "    This will return a JSON-formatted dictionary with location details.\n"
        "\nArguments:\n"
        "    ip_address (str): A valid IPv4 or IPv6 address (e.g., \"8.8.8.8\").\n"
        "\nReturns:\n"
        "    JSON-formatted dictionary containing:\n"
        "        - IP (str): The IP address.\n"
        "        - City (str): The city where the IP is located.\n"
        "        - Region (str): The region/state.\n"
        "        - Country (str): The country code.\n"
        "        - Latitude, Longitude (str): The approximate location.\n"
        "        - ISP (str): The Internet Service Provider.\n"
        "\nError Handling:\n"
        "    - Returns an error message if the request fails.\n"
    )
    return help_text
