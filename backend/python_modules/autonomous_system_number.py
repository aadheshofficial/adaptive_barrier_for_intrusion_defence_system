import requests

def get_asn(ip_address: str) -> str:
    """
    Retrieves the ASN (Autonomous System Number) information for a given IP address using ipinfo.io.

    Args:
        ip_address (str): The IP address to look up.

    Returns:
        str: The ASN organization name or an error message.
    """
    api_url = f"https://ipinfo.io/{ip_address}/json"
    
    try:
        response = requests.get(api_url, timeout=5)
        response.raise_for_status()

        data = response.json()
        asn_info = data.get("org", "ASN information not available")

        return asn_info

    except requests.exceptions.Timeout:
        return "Error: Request timed out. Please try again."

    except requests.exceptions.ConnectionError:
        return "Error: Unable to connect to the IP info service."

    except requests.exceptions.HTTPError as http_err:
        return f"HTTP Error: {http_err}"

    except requests.exceptions.RequestException as e:
        return f"Unexpected Error: {e}"


def help() -> None:
    """
    Displays usage instructions for the get_asn function.

    This function explains how to use the get_asn function to fetch ASN information for a given IP address.
    
    Usage:
        - Call get_asn(ip_address) with a valid IP address.
        - Example:
            asn_info = get_asn("8.8.8.8")
            print(asn_info)

    Parameters:
        - ip_address (str): A valid IPv4 or IPv6 address.

    Returns:
        None
    """
    help_text = (
        "\nUsage Instructions:\n"
        "=====================\n"
        "This script fetches the ASN (Autonomous System Number) for a given IP address.\n"
        "\nUsage:\n"
        "    Call the function get_asn(ip_address) with a valid IP.\n"
        "\nExample:\n"
        "    asn_info = get_asn(\"8.8.8.8\")\n"
        "    print(asn_info)\n"
        "\nParameters:\n"
        "    - ip_address (str): A valid IPv4 or IPv6 address.\n"
        "\nError Handling:\n"
        "    - Handles connection errors, timeouts, and HTTP errors.\n"
        "\nReturns:\n"
        "    - ASN information as a string or an error message.\n"
    )
    return help_text
