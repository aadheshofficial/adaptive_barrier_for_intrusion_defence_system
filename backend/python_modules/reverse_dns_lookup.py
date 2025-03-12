import socket

def get_domain_name(ip:str)->str:
    """
    Retrieves the domain name associated with a given IP address using reverse DNS lookup.

    Args:
        ip (str): The IP address to look up.

    Returns:
        str: The domain name if found, otherwise an error message.
    """
    try:
        domain_name = socket.gethostbyaddr(ip)
        return domain_name[0]
    except socket.herror:
        return f"No domain name found for IP {ip}"

def help():
    """
    Provides detailed instructions on how to use the get_domain_name function.

    Example:
        hostname = get_domain_name("8.8.8.8")
        print(hostname)

    This will return the domain name associated with the given IP address.

    Returns:
        None
    """
    help_text = (
        "\nUsage:\n"
        "    Call the function get_domain_name(ip) with a valid IP address.\n"
        "    Example:\n"
        "        hostname = get_domain_name(\"8.8.8.8\")\n"
        "        print(hostname)\n"
        "    This will return and print the domain name associated with the given IP address.\n"
        "\nArguments:\n"
        "    ip (str): A valid IPv4 or IPv6 address (e.g., \"8.8.8.8\").\n"
        "\nReturns:\n"
        "    str: The domain name if found, otherwise an error message.\n"
        "\nError Handling:\n"
        "    - If no domain name is found, an error message will be returned.\n"
    )
    return help_text
