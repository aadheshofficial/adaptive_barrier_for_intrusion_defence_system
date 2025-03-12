import os
import platform

def is_host_up(host: str) -> bool:
    """
    Checks if a host is reachable.

    Args:
        host (str): The hostname or IP address to check.

    Returns:
        bool: True if the host is up, False otherwise.
    """
    param = "-n 1" if platform.system().lower() == "windows" else "-c 1"
    response = os.system(f"ping {param} {host} >nul 2>&1" if platform.system().lower() == "windows" 
                         else f"ping {param} {host} >/dev/null 2>&1")
    return response == 0


def help():
    """
    Provides detailed instructions on how to use the is_host_up function.

    Example:
        status = is_host_up("www.google.com")
        print(status)

    This will return True if the host is reachable, otherwise False.

    Returns:
        None
    """
    help_text = (
        "\nUsage:\n"
        "    Call the function is_host_up(host) with a valid domain or IP address.\n"
        "    Example:\n"
        "        status = is_host_up(\"www.google.com\")\n"
        "        print(status)\n"
        "    This will return True if the host is reachable, otherwise False.\n"
        "\nArguments:\n"
        "    host (str): A valid domain name or IP address (e.g., \"www.google.com\" or \"8.8.8.8\").\n"
        "\nReturns:\n"
        "    bool: True if the host is reachable, False if not.\n"
        "\nError Handling:\n"
        "    - If the host is unreachable or invalid, the function will return False.\n"
    )
    return help_text
