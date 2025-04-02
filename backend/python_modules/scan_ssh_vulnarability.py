import nmap

def scan_vulnerable_ssh(ip: str, port: int) -> dict:
    """
    Scans a given IP and port for SSH vulnerabilities using Nmap's NSE scripts.

    Args:
        ip (str): The target IP address to scan.
        port (int): The specific port to check for SSH vulnerabilities.

    Returns:
        dict: A dictionary containing detected SSH vulnerabilities.
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=ip, ports=str(port), 
            arguments="--script ssh-auth-methods,ssh2-enum-algos,ssh-hostkey,ssh-run,ssh-brute,ssh-publickey-acceptance"
            # arguments="-Pn --script ssh-auth-methods,ssh2-enum-algos,ssh-hostkey,ssh-run,ssh-banner,ssh-publickey-acceptance,ssh-known-hosts,ssh-version,ssh-config,ssh-debug-info"
            )

    results = {}
    port=int(port)
    print(nm.get_nmap_last_output())
    if ip in nm.all_hosts():
        for proto in nm[ip].all_protocols():
            if port in nm[ip][proto]:
                print("hello")
                script_results = nm[ip][proto][port].get("script", {})
                if script_results:
                    results[port] = script_results  

    return results  

def help():
    """
    Provides usage instructions for the scan_vulnerable_ssh function.

    Example:
        ssh_vulns = scan_vulnerable_ssh("192.168.1.1", 22)
        print(ssh_vulns)

    This scans a given IP and port for SSH vulnerabilities using Nmap.

    Returns:
        dict: A dictionary containing detected SSH vulnerabilities.
    """
    help_text = (
        "\nUsage:\n"
        "    Call the function scan_vulnerable_ssh(ip, port) with a valid IP address and port number.\n"
        "    Example:\n"
        "        ssh_vulns = scan_vulnerable_ssh(\"192.168.1.1\", 22)\n"
        "        print(ssh_vulns)\n"
        "    This scans the given IP's SSH service on the specified port for known vulnerabilities using Nmap NSE scripts.\n"
        "\nFeatures Scanned:\n"
        "    - SSH authentication methods (ssh-auth-methods).\n"
        "    - Brute force protection (ssh-brute).\n"
        "    - SSH encryption algorithms enumeration (ssh2-enum-algos).\n"
        "    - General SSH vulnerabilities (ssh-vuln*).\n"
        "    - SSL/TLS misconfigurations (ssl* for SSH over SSL).\n"
        "    - SSH host key retrieval (ssh-hostkey).\n"
        "    - Remote command execution check (ssh-run).\n"
        "    - SSH banner grabbing (ssh-banner).\n"
        "    - Public key acceptance test (ssh-publickey-acceptance).\n"
        "    - SSH known hosts enumeration (ssh-known-hosts).\n"
        "    - SSH version detection (ssh-version).\n"
        "    - SSH configuration analysis (ssh-config).\n"
        "    - SSH debug information retrieval (ssh-debug-info).\n"
        "    - SSH HMAC algorithm enumeration (ssh-hmac-algos).\n"
        "    - SSH authorized keys ownership check (ssh-auth-owners).\n"
        "    - SSH security audit (ssh-audit).\n"
        "    - SSH tracing for debugging (ssh-trace).\n"
        "    - SSH version 1 support detection (sshv1-support).\n"
        "    - TLS vulnerabilities (tls-ticketbleed, tls-heartbleed, ssl-dh-params, ssl-cert-intact, ssl-poodle, ssl-ccs-injection).\n"
        "    - SSL/TLS cipher enumeration (ssl-enum-ciphers).\n"
        "    - SSL/TLS date validation (ssl-date).\n"
        "    - Enables additional aggressive checks with unsafe arguments.\n"
        "\nArguments:\n"
        "    ip (str): A valid IPv4 address (e.g., \"192.168.1.1\").\n"
        "    port (int): The port number to scan (default SSH port is 22, but custom ports are supported).\n"
        "\nReturns:\n"
        "    dict: A dictionary with detected SSH vulnerabilities.\n"
        "\nNotes:\n"
        "    - Requires Nmap and SSH-related NSE scripts to be installed.\n"
        "    - Ensure you have permission before scanning external IPs.\n"
        "    - Supports custom SSH ports (e.g., 2222, 2022).\n"
        "    - Uses unsafe script arguments for deeper scanning.\n"
    )
    return help_text
