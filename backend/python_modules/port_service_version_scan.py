import nmap

def find_service_version(ip: str, port: int) -> dict | None:
    """
    Uses Nmap to find the service and version running on a specific port.

    Args:
        ip (str): The target IP address to scan.
        port (int): The port number to check.

    Returns:
        dict | None: A dictionary containing port, protocol, status, service, and version,
                     or None if an error occurs.
    """
    nm = nmap.PortScanner()

    try:
        nm.scan(hosts=ip, ports=str(port), arguments="-sV")
        port = int(port)
        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                if port in nm[ip][proto]:
                    state = nm[ip][proto][port].get('state', 'closed/filtered')
                    service = nm[ip][proto][port].get('name', 'unknown')
                    version = nm[ip][proto][port].get('version', 'unknown')

                    result = {
                        "port": port,
                        "protocol": proto,
                        "status": state,
                        "service": service,
                        "version": version,
                    }
                    return result

        return None

    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def help():
    """
    Provides usage instructions for the find_service_version function.

    Example:
        service_info = find_service_version("8.8.8.8", 443)
        print(service_info)

    This will use Nmap to detect the service and version running on a given IP and port.

    Returns:
        dict | None
    """
    help_text = (
        "\nUsage:\n"
        "    Call the function find_service_version(ip, port) with a valid IP and port.\n"
        "    Example:\n"
        "        service_info = find_service_version(\"8.8.8.8\", 443)\n"
        "        print(service_info)\n"
        "    This will use Nmap to detect the service and version running on the specified port.\n"
        "\nArguments:\n"
        "    ip (str): A valid IPv4 address (e.g., \"8.8.8.8\").\n"
        "    port (int): The port number to check (e.g., 443 for HTTPS).\n"
        "\nReturns:\n"
        "    dict | None: A dictionary with port, protocol, status, service, and version details.\n"
        "                 Returns None if the scan fails.\n"
    )
    return help_text

