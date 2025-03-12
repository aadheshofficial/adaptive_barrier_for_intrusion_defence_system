import nmap

def scan_open_ports(ip):
    """
    Scans a given IP address for open ports using Nmap.

    Args:
        ip (str): The target IP address to scan.

    Returns:
        dict: A dictionary where keys are open port numbers and values are their state.
    """
    nm = nmap.PortScanner()

    print(f"Scanning {ip} for open ports...\n")

    nm.scan(hosts=ip, arguments="--open")

    results = {}

    if ip in nm.all_hosts():
        for proto in nm[ip].all_protocols():
            for port in nm[ip][proto]:
                state = nm[ip][proto][port]['state']
                results[port] = state
                print(f"Port {port}: {state}")

    return results

def help():
    """
    Provides usage instructions for the check_open_ports function.

    Example:
        open_ports = check_open_ports("8.8.8.8")
        print(open_ports)

    This scans the **most common 1,000 ports** on the given IP and returns a dictionary of open ports.

    Returns:
        None
    """
    help_text = (
        "\nUsage:\n"
        "    Call the function check_open_ports(ip) with a valid IP address.\n"
        "    Example:\n"
        "        open_ports = check_open_ports(\"8.8.8.8\")\n"
        "        print(open_ports)\n"
        "    This will scan the **most common 1,000 ports** on the given IP and return a dictionary of open ports.\n"
        "\nArguments:\n"
        "    ip (str): A valid IPv4 address (e.g., \"8.8.8.8\").\n"
        "\nReturns:\n"
        "    dict: A dictionary where the keys are **open port numbers** and values are their state ('open').\n"
        "\nNotes:\n"
        "    - This scan covers only the **1,000 most commonly used ports**.\n"
        "    - The function **only returns open ports** (closed ports are ignored).\n"
        "    - To scan **all 65,535 ports**, use '-p 1-65535' in the scan arguments.\n"
    )
    return help_text
