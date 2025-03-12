import socket

def get_ip_of_domain(domain:str)->str:
    """
    Retrieves the IP address associated with a given domain name using DNS lookup.

    Args:
        domain (str): The domain name to look up.

    Returns:
        str: The IP address if found, otherwise an error message.
    """
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address 
    except socket.gaierror:
        return f"Failed to get IP address for domain {domain}"

def help():
    """
    Provides detailed instructions on how to use the get_ip_of_domain function.

    Example:
        ip = get_ip_of_domain("www.google.com")
        print(ip)

    This will return the IP address associated with the given domain name.

    Returns:
        None
    """
    help_text = (
        "\nUsage:\n"
        "    Call the function get_ip_of_domain(domain) with a valid domain name.\n"
        "    Example:\n"
        "        ip = get_ip_of_domain(\"www.google.com\")\n"
        "        print(ip)\n"
        "    This will return and print the IP address associated with the given domain name.\n"
        "\nArguments:\n"
        "    domain (str): A valid domain name (e.g., \"www.google.com\").\n"
        "\nReturns:\n"
        "    str: The IP address if found, otherwise an error message.\n"
        "\nError Handling:\n"
        "    - If the domain cannot be resolved, an error message will be returned.\n"
    )
    return help_text
