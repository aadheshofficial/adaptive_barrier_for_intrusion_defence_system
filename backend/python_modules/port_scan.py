import nmap

def check_port_status(ip: str, port: int) -> bool:
    """
    Checks if a specific port is open on a given IP using Nmap.

    Args:
        ip (str): The target IP address to scan.
        port (int): The specific port to check.

    Returns:
        bool: True if the port is open, False if closed or filtered.
    """
    nm = nmap.PortScanner()
    nm.scan(ip, str(port))
    port=int(port)
    if ip in nm.all_hosts():
        for proto in nm[ip].all_protocols():
            if port in nm[ip][proto]:
                state = nm[ip][proto][port].get('state', 'closed/filtered')
                if state == 'open':
                    return "Open"

    return "closed"

def help():
    """
    Provides usage instructions for the check_port_status function.

    Example:
        is_open = check_port_status("8.8.8.8", 443)
        print(is_open)

    This checks if the specified port is open on the given IP.

    Returns:
        bool: True if the port is open, False if closed or filtered.
    """
    help_text = (
        "\nUsage:\n"
        "    Call the function check_port_status(ip, port) with a valid IP address and port.\n"
        "    Example:\n"
        "        is_open = check_port_status(\"8.8.8.8\", 443)\n"
        "        print(is_open)\n"
        "    This checks if the specified port is open on the given IP.\n"
        "\nArguments:\n"
        "    ip (str): A valid IPv4 address (e.g., \"8.8.8.8\").\n"
        "    port (int): The port number to check (e.g., 443 for HTTPS, 22 for SSH).\n"
        "\nReturns:\n"
        "    bool: True if the port is open, False if closed or filtered.\n"
        "\nNotes:\n"
        "    - Requires Nmap to be installed on the system.\n"
        "    - Uses Nmap scanning to determine port status.\n"
        "    - If the port is closed or filtered, the function returns False.\n"
    )
    return help_text
