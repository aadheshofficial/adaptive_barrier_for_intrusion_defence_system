import nmap

def check_top_protocol_ports(ip):
    """
    Scans a given IP address for open ports.

    Args:
        ip (str): The target IP address to scan.

    Returns:
        dict: A dictionary where keys are port numbers and values are their state (open/closed).
    """
    nm = nmap.PortScanner()

    ports_to_check = [
    21, 22, 23, 25, 53, 80, 110, 143, 161, 389, 443, 445, 587, 993, 995,
    3306, 3389, 1521, 1433, 27017, 6379, 5432, 500, 1194, 5900, 8080, 8443,
    3128, 1080, 1883, 1900, 5353, 6667
    ]

    ports_str = ",".join(map(str, ports_to_check))

    # print(f"Scanning {ip} for open ports...\n")
    nm.scan(hosts=ip, ports=ports_str, arguments="--open")

    results = {port: "closed/filtered" for port in ports_to_check}  # Default all to closed/filtered

    if ip in nm.all_hosts():
        for proto in nm[ip].all_protocols():
            for port in nm[ip][proto]:
                results[port] = "open"  # Update detected open ports
                # print(f"Port {port}: open")

    return results

def help():
    """
    Provides detailed instructions on how to use the check_open_ports function.

    Example:
        results = check_open_ports("8.8.8.8")
        print(results)

    This will scan the given IP address and return a dictionary of open/closed ports.

    Returns:
        None
    """
    help_text = (
        "\nUsage:\n"
        "    Call the function check_open_ports(ip) with a valid IP address.\n"
        "    Example:\n"
        "        results = check_open_ports(\"8.8.8.8\")\n"
        "        print(results)\n"
        "    This will scan the given IP address and return a dictionary of open/closed ports.\n"
        "\nArguments:\n"
        "    ip (str): A valid IPv4 address (e.g., \"8.8.8.8\").\n"
        "\nReturns:\n"
        "    dict: A dictionary where the keys are port numbers and values are their state ('open' or 'closed/filtered').\n"
    )
    return help_text
