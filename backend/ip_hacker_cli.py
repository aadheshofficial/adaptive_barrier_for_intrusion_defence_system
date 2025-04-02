import pyfiglet
import shutil
from termcolor import colored
import colorama
from python_modules import check_host_status
from python_modules import autonomous_system_number
from python_modules import dns_lookup
from python_modules import reverse_dns_lookup
from python_modules import scan_top_open_ports
from python_modules import scan_open_vulnerability
from python_modules import port_scan
from python_modules import port_service_version_scan
from python_modules import scan_popular_ports
from python_modules import locate_ip_address
from python_modules import load_coordinates_on_map
from python_modules import scan_ftp_vulnerability
from python_modules import scan_ssh_vulnarability
from python_modules import scan_telnet_vulnerability
from python_modules import scan_smtp_vulnerability
from python_modules import scan_dns_vulnerability
from python_modules import scan_http_vulnerability
from python_modules import scan_pop3_vulnerability
from python_modules import scan_imap_vulnerability
from python_modules import scan_snmp_vulnerability
from python_modules import scan_https_vulnerability
from python_modules import scan_smb_vulnerability
from python_modules import scan_smtp_ssl_vulnerability
from python_modules import scan_imap_ssl_vulnerability
from python_modules import scan_pop3_ssl_vulnerability
from python_modules import scan_mysql_vulnerability
from python_modules import scan_rdp_vulnerability
from python_modules import scan_oracle_db_vulnerability
from python_modules import scan_mssql_vulnerability
from python_modules import scan_mongo_db_vulnerability
from python_modules import scan_redis_vulnerability
import time
import itertools
import sys
import threading

colorama.init()
columns = shutil.get_terminal_size().columns
import os

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def print_banner(title:str)->None:
    banner = pyfiglet.figlet_format(title, font="larry3d")
    print()
    print(colored(banner, "red"), end="")
    print(colored("=" * 78, "red"))
    print()

item_list = [
    "Check host status", "Find Autonomous System Number",
    "DNS lookup", "Reverse DNS lookup", "Scan top protocol ports",
    "Scan open ports of an IP", "Scan a particular port of an IP", "Scan port service & version",
    "Scan for open vulnerabilities", "Find location of the IP address", 
    "Load coordinates on Google Map", "Scan vulnerable FTP",
    "Scan vulnerable SSH", "Scan vulnerable Telnet", "Scan vulnerable SMTP",
    "Scan vulnerable DNS", "Scan vulnerable HTTP", "Scan vulnerable POP3",
    "Scan vulnerable IMAP", "Scan vulnerable SNMP", "Scan vulnerable HTTPS",
    "Scan vulnerable SMB", "Scan vulnerable SMTP SSL", "Scan vulnerable IMAP SSL",
    "Scan vulnerable POP3 SSL", "Scan vulnerable MySQL", "Scan vulnerable RDP",
    "Scan vulnerable OracleDB", "Scan vulnerable MSSQL", "Scan vulnerable MongoDB",
    "Scan vulnerable Redis"
]


def print_centered_title(title, num_cols, col_width):
    title_text = f"[ {title} ]"
    if num_cols >2 :
        total_width = (num_cols * col_width) + ((num_cols - 1) * 2)
        left_padding = (total_width - (len(title_text)*2)) // 2
    else:
        terminal_width = shutil.get_terminal_size().columns
        title_length = len(title)
        left_padding = (terminal_width - title_length) // 2
    print(" " * max(left_padding, 0) + colored(title_text, "yellow"))


def print_items(item_list,title):
    bracket_color = "cyan"
    number_color = "green"
    item_color = "red"

    print()
    if columns >= 100:
        num_cols = 3
        col_width = 40
    elif columns >= 70:
        num_cols = 2
        col_width = 50
    else:
        num_cols = 1 
        col_width = 70

    print_centered_title(title,num_cols,col_width)
    print()
    if num_cols == 1:
        for i, item in enumerate(item_list, start=1):
            print(f"{colored('[', bracket_color)}{colored(str(i).rjust(2), number_color)}{colored('] ', bracket_color)}"
                  f"{colored(item, item_color)}")
    else:
        rows = -(-len(item_list) // num_cols) 
        for i in range(rows):
            line = ""
            for j in range(num_cols):
                index = i + j * rows
                if index < len(item_list):
                    formatted_item = (
                        f"{colored('[', bracket_color)}{colored(str(index+1).rjust(2), number_color)}{colored('] ', bracket_color)}"
                        f"{colored(item_list[index].ljust(col_width - 6), item_color)}"
                    )
                    line += formatted_item
            print(line)

    print()

def format_nmap_results(scan_results: dict) -> str:
    formatted_output = """### Nmap Scan Results\n"""
    
    for port, data in scan_results.items():
        formatted_output += f"\n#### Port: {port}\n"
        
        for script, output in data.items():
            formatted_output += f"- **{script.replace('-', ' ').title()}**\n"
            
            if 'VULNERABLE' in output:
                formatted_output += "  - **State:** VULNERABLE (Exploitable)\n"
                
                if 'CVE' in output:
                    cve_index = output.find('CVE:')
                    cve = output[cve_index:].split('\n')[0] if cve_index != -1 else "Unknown"
                    formatted_output += f"  - **{cve}**\n"
                
                if 'Exploit results:' in output:
                    exploit_start = output.find('Exploit results:')
                    exploit_data = output[exploit_start:].splitlines() if exploit_start != -1 else []
                    for line in exploit_data:
                        formatted_output += f"    - {line.strip()}\n"
                
                formatted_output += "\n  - **References:**\n"
                for ref in output.splitlines():
                    if 'http' in ref:
                        formatted_output += f"    - {ref.strip()}\n"
                
            else:
                formatted_output += "  - " + "\n  - ".join(output.strip().splitlines()) + "\n"
    
    return formatted_output

def loading_animation(stop_event):
    spinner = itertools.cycle(["-", "\\", "|", "/"])
    
    while not stop_event.is_set():
        sys.stdout.write(f"\rLoading please wait {next(spinner)}")
        sys.stdout.flush()
        time.sleep(0.1)
    
    sys.stdout.write("\r" + " " * 30 + "\r")  
    sys.stdout.flush()

def check_host_status_1():
    clear_screen()
    print_banner("Host Status")
    print(colored(check_host_status.help(), "yellow"))
    
    while True:
        host = input(colored("Enter the host (IP or domain): ", "cyan")).strip()
        if not host:
            print(colored("Invalid input! Please enter a valid host.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = check_host_status.is_host_up(host)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{host} is UP!", "green"))
    else:
        print(colored(f"\n{host} is DOWN!", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))

    
def find_asn():
    clear_screen()
    print_banner("Autonomous System Number")
    print(colored(autonomous_system_number.help(),"yellow"))
    while True:
        host = input(colored("Enter the host (IPv4 or IPv6): ", "cyan")).strip()
        if not host:
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = autonomous_system_number.get_asn(host)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{result}", "green"))
    else:
        print(colored(f"\nError connecting to {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))

def dns():
    clear_screen()
    print_banner("DNS Lookup")
    print(colored(dns_lookup.help(),"yellow"))

    while True:
        host = input(colored("Enter the host (domain name): ", "cyan")).strip()
        if not host:
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = dns_lookup.get_ip_of_domain(host)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{result}", "green"))
    else:
        print(colored(f"\nError connecting to {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))

def rev_dns():
    clear_screen()
    print_banner("Reverse DNS Lookup")
    print(colored(reverse_dns_lookup.help(),"yellow"))

    while True:
        host = input(colored("Enter the ip (ip address): ", "cyan")).strip()
        if not host:
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = reverse_dns_lookup.get_domain_name(host)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{result}", "green"))
    else:
        print(colored(f"\nNo result found for {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))

def s_top_prot():
    clear_screen()
    print_banner("Scan Top ports")
    print(colored(scan_top_open_ports.help(),"yellow"))

    while True:
        host = input(colored("Enter the ip (ip address): ", "cyan")).strip()
        if not host:
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = scan_top_open_ports.scan_open_ports(host)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{result}", "green"))
    else:
        print(colored(f"\nNo result found for {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))

def s_open_prot():
    clear_screen()
    print_banner("Scan open ports")
    print(colored(scan_popular_ports.help(),"yellow"))

    while True:
        host = input(colored("Enter the ip (ip address): ", "cyan")).strip()
        if not host:
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = scan_popular_ports.check_top_protocol_ports(host)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{format_nmap_results(result)}", "green"))
    else:
        print(colored(f"\nNo result found for {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))

def s_prot():
    clear_screen()
    print_banner("Scan port")
    print(colored(port_scan.help(),"yellow"))

    while True:
        host = input(colored("Enter the ip (ip address): ", "cyan")).strip()
        port = input(colored("Enter the port (22): ", "cyan")).strip()
        
        if not host or not port :
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = port_scan.check_port_status(host,port)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{result}", "green"))
    else:
        print(colored(f"\nNo result found for {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))


def s_serv_prot():
    clear_screen()
    print_banner("Scan service version")
    print(colored(port_service_version_scan.help(),"yellow"))

    while True:
        host = input(colored("Enter the ip (ip address): ", "cyan")).strip()
        port = input(colored("Enter the port (22): ", "cyan")).strip()
        
        if not host or not port:
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = port_service_version_scan.find_service_version(host,port)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{result}", "green"))
    else:
        print(colored(f"\nNo result found for {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))

def s_open_vul():
    clear_screen()
    print_banner("Scan open ports")
    print(colored(scan_open_vulnerability.help(),"yellow"))

    while True:
        host = input(colored("Enter the ip (ip address): ", "cyan")).strip()
        if not host:
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = scan_open_vulnerability.scan_vulnerabilities(host)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{result}", "green"))
    else:
        print(colored(f"\nNo result found for {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))

def find_loc():
    clear_screen()
    print_banner("Locate IP")
    print(colored(locate_ip_address.help(),"yellow"))

    while True:
        host = input(colored("Enter the ip (ip address): ", "cyan")).strip()
        
        if not host :
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = locate_ip_address.get_geolocation(host)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{result}", "green"))
    else:
        print(colored(f"\nNo result found for {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))

def load_cor():
    clear_screen()
    print_banner("Load coordinates")
    print(colored(load_coordinates_on_map.help(),"yellow"))

    while True:
        lat = input(colored("Enter the latitude : ", "cyan")).strip()
        lon = input(colored("Enter the longitude : ", "cyan")).strip()
        
        if not lat or not lon :
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if lat == "q":
            return "q"
        if lat and lon:
            break
    load_coordinates_on_map.open_coordinates_in_map(lat,lon)  


def s_ftp():
    clear_screen()
    print_banner("FTP")
    print(colored(scan_ftp_vulnerability.help(),"yellow"))

    while True:
        host = input(colored("Enter the ip (ip address): ", "cyan")).strip()
        port = input(colored("Enter the port (21): ", "cyan")).strip()
        
        if not host or not port:
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = scan_ftp_vulnerability.scan_vulnerable_ftp(host,port)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{format_nmap_results(result)}", "green"))
        # print(format_nmap_results(result))
    else:
        print(colored(f"\nNo result found for {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))

def s_ssh():
    clear_screen()
    print_banner("SSH")
    print(colored(scan_ssh_vulnarability.help(),"yellow"))

    while True:
        host = input(colored("Enter the ip (ip address): ", "cyan")).strip()
        port = input(colored("Enter the port (22): ", "cyan")).strip()
        
        if not host or not port:
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = scan_ssh_vulnarability.scan_vulnerable_ssh(host,port)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{format_nmap_results(result)}", "green"))
    else:
        print(colored(f"\nNo result found for {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))


def s_telnet():
    clear_screen()
    print_banner("Telnet")
    print(colored(scan_telnet_vulnerability.help(),"yellow"))

    while True:
        host = input(colored("Enter the ip (ip address): ", "cyan")).strip()
        port = input(colored("Enter the port (23): ", "cyan")).strip()
        
        if not host or not port:
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = scan_telnet_vulnerability.scan_vulnerable_telnet(host,port)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{format_nmap_results(result)}", "green"))
    else:
        print(colored(f"\nNo result found for {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))


def s_smtp():
    clear_screen()
    print_banner("SMTP")
    print(colored(scan_smtp_vulnerability.help(),"yellow"))

    while True:
        host = input(colored("Enter the ip (ip address): ", "cyan")).strip()
        port = input(colored("Enter the port (25): ", "cyan")).strip()
        
        if not host or not port:
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = scan_smtp_vulnerability.scan_vulnerable_smtp(host,port)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{format_nmap_results(result)}", "green"))
    else:
        print(colored(f"\nNo result found for {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))


def s_dns():
    clear_screen()
    print_banner("DNS")
    print(colored(scan_dns_vulnerability.help(),"yellow"))

    while True:
        host = input(colored("Enter the ip (ip address): ", "cyan")).strip()
        port = input(colored("Enter the port (53): ", "cyan")).strip()
        
        if not host or not port:
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = scan_dns_vulnerability.scan_vulnerable_dns(host,port)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{format_nmap_results(result)}", "green"))
    else:
        print(colored(f"\nNo result found for {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))


def s_http():
    clear_screen()
    print_banner("HTTP")
    print(colored(scan_http_vulnerability.help(),"yellow"))

    while True:
        host = input(colored("Enter the ip (ip address): ", "cyan")).strip()
        port = input(colored("Enter the port (80): ", "cyan")).strip()
        
        if not host or not port:
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = scan_http_vulnerability.scan_vulnerable_http(host,port)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{format_nmap_results(result)}", "green"))
    else:
        print(colored(f"\nNo result found for {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))


def s_pop3():
    clear_screen()
    print_banner("POP3")
    print(colored(scan_pop3_vulnerability.help(),"yellow"))

    while True:
        host = input(colored("Enter the ip (ip address): ", "cyan")).strip()
        port = input(colored("Enter the port (110): ", "cyan")).strip()
        
        if not host or not port:
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = scan_pop3_vulnerability.scan_vulnerable_pop3(host,port)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{format_nmap_results(result)}", "green"))
    else:
        print(colored(f"\nNo result found for {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))


def s_imap():
    clear_screen()
    print_banner("IMAP")
    print(colored(scan_imap_vulnerability.help(),"yellow"))

    while True:
        host = input(colored("Enter the ip (ip address): ", "cyan")).strip()
        port = input(colored("Enter the port (143): ", "cyan")).strip()
        
        if not host or not port:
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = scan_imap_vulnerability.scan_vulnerable_imap(host,port)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{format_nmap_results(result)}", "green"))
    else:
        print(colored(f"\nNo result found for {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))


def s_snmp():
    clear_screen()
    print_banner("SNMP")
    print(colored(scan_snmp_vulnerability.help(),"yellow"))

    while True:
        host = input(colored("Enter the ip (ip address): ", "cyan")).strip()
        port = input(colored("Enter the port (161): ", "cyan")).strip()
        
        if not host or not port:
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = scan_snmp_vulnerability.scan_vulnerable_snmp(host,port)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{format_nmap_results(result)}", "green"))
    else:
        print(colored(f"\nNo result found for {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))


def s_https():
    clear_screen()
    print_banner("HTTPS")
    print(colored(scan_https_vulnerability.help(),"yellow"))

    while True:
        host = input(colored("Enter the ip (ip address): ", "cyan")).strip()
        port = input(colored("Enter the port (443): ", "cyan")).strip()
        
        if not host or not port:
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = scan_https_vulnerability.scan_vulnerable_https(host,port)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{format_nmap_results(result)}", "green"))
    else:
        print(colored(f"\nNo result found for {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))


def s_smb():
    clear_screen()
    print_banner("SMB")
    print(colored(scan_smb_vulnerability.help(),"yellow"))

    while True:
        host = input(colored("Enter the ip (ip address): ", "cyan")).strip()
        port = input(colored("Enter the port (445): ", "cyan")).strip()
        
        if not host or not port:
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = scan_smb_vulnerability.scan_vulnerable_smb(host,port)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{format_nmap_results(result)}", "green"))
    else:
        print(colored(f"\nNo result found for {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))


def s_smtp_s():
    clear_screen()
    print_banner("SMTP SSL")
    print(colored(scan_smtp_ssl_vulnerability.help(),"yellow"))

    while True:
        host = input(colored("Enter the ip (ip address): ", "cyan")).strip()
        port = input(colored("Enter the port (587): ", "cyan")).strip()
        
        if not host or not port:
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = scan_smtp_ssl_vulnerability.scan_vulnerable_smtp_submission(host,port)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{format_nmap_results(result)}", "green"))
    else:
        print(colored(f"\nNo result found for {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))


def s_imap_s():
    clear_screen()
    print_banner("IMAP SSL")
    print(colored(scan_imap_ssl_vulnerability.help(),"yellow"))

    while True:
        host = input(colored("Enter the ip (ip address): ", "cyan")).strip()
        port = input(colored("Enter the port (993): ", "cyan")).strip()
        
        if not host or not port:
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = scan_imap_ssl_vulnerability.scan_vulnerable_imap_ssl(host,port)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{format_nmap_results(result)}", "green"))
    else:
        print(colored(f"\nNo result found for {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))


def s_pop3_s():
    clear_screen()
    print_banner("POP3 SSL")
    print(colored(scan_pop3_ssl_vulnerability.help(),"yellow"))

    while True:
        host = input(colored("Enter the ip (ip address): ", "cyan")).strip()
        port = input(colored("Enter the port (995): ", "cyan")).strip()
        
        if not host or not port:
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = scan_pop3_ssl_vulnerability.scan_vulnerable_pop3_ssl(host,port)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{format_nmap_results(result)}", "green"))
    else:
        print(colored(f"\nNo result found for {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))


def s_mysql():
    clear_screen()
    print_banner("MYSQL")
    print(colored(scan_mysql_vulnerability.help_mysql(),"yellow"))

    while True:
        host = input(colored("Enter the ip (ip address): ", "cyan")).strip()
        port = input(colored("Enter the port (3306): ", "cyan")).strip()
        
        if not host or not port:
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = scan_mysql_vulnerability.scan_vulnerable_mysql(host,port)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{format_nmap_results(result)}", "green"))
    else:
        print(colored(f"\nNo result found for {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))


def s_rdp():
    clear_screen()
    print_banner("RDP")
    print(colored(scan_rdp_vulnerability.help(),"yellow"))

    while True:
        host = input(colored("Enter the ip (ip address): ", "cyan")).strip()
        port = input(colored("Enter the port (3389): ", "cyan")).strip()
        
        if not host or not port:
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = scan_rdp_vulnerability.scan_vulnerable_rdp(host,port)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{format_nmap_results(result)}", "green"))
    else:
        print(colored(f"\nNo result found for {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))


def s_oracle():
    clear_screen()
    print_banner("ORACLE DB")
    print(colored(scan_oracle_db_vulnerability.help(),"yellow"))

    while True:
        host = input(colored("Enter the ip (ip address): ", "cyan")).strip()
        port = input(colored("Enter the port (1521): ", "cyan")).strip()
        
        if not host or not port:
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = scan_oracle_db_vulnerability.scan_vulnerable_oracledb(host,port)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{format_nmap_results(result)}", "green"))
    else:
        print(colored(f"\nNo result found for {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))


def s_mssql():
    clear_screen()
    print_banner("MSSQL")
    print(colored(scan_mssql_vulnerability.help_mssql(),"yellow"))

    while True:
        host = input(colored("Enter the ip (ip address): ", "cyan")).strip()
        port = input(colored("Enter the port (1433): ", "cyan")).strip()
        
        if not host or not port:
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = scan_mssql_vulnerability.scan_vulnerable_mssql(host,port)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{format_nmap_results(result)}", "green"))
    else:
        print(colored(f"\nNo result found for {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))


def s_mongodb():
    clear_screen()
    print_banner("MONGO DB")
    print(colored(scan_mongo_db_vulnerability.help(),"yellow"))

    while True:
        host = input(colored("Enter the ip (ip address): ", "cyan")).strip()
        port = input(colored("Enter the port (27017): ", "cyan")).strip()
        
        if not host or not port:
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = scan_mongo_db_vulnerability.scan_vulnerable_mongodb(host,port)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{format_nmap_results(result)}", "green"))
    else:
        print(colored(f"\nNo result found for {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))


def s_redis():
    clear_screen()
    print_banner("REDIS")
    print(colored(scan_redis_vulnerability.help(),"yellow"))

    while True:
        host = input(colored("Enter the ip (ip address): ", "cyan")).strip()
        port = input(colored("Enter the port (6379): ", "cyan")).strip()
        
        if not host or not port:
            print(colored("Invalid input! Please enter a valid input.", "red"))
        if host == "q":
            return "q"
        if host:
            break

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()
    result = scan_redis_vulnerability.scan_vulnerable_redis(host,port)  
    stop_event.set()
    loader_thread.join()

    if result:
        print(colored(f"\n{format_nmap_results(result)}", "green"))
    else:
        print(colored(f"\nNo result found for {host}", "red"))

    input(colored("\nPress Enter to continue...", "yellow"))


if __name__ == "__main__":
    while True:
        clear_screen()
        print_banner("IP Hacker")
        print_items(item_list,title="SCANNING OPTIONS")
        choice = input(colored("\nEnter your choice (or 'q' to quit): ", "yellow")).strip().lower()
        if choice == "q":
            print(colored("\nExiting...\n", "red"))
            break
        elif choice.isdigit() and 1 <= int(choice) <= len(item_list):
            choice = int(choice)
            if choice == 1:
                q = check_host_status_1()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 2:
                q = find_asn()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 3:
                q = dns()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 4:
                q = rev_dns()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 5:
                q = s_top_prot()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 6:
                q = s_open_prot()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 7:
                q = s_prot()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 8:
                q = s_serv_prot()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 9:
                q = s_open_vul()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 10:
                q = find_loc()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 11:
                q = load_cor()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 12:
                q = s_ftp()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 13:
                q = s_ssh()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 14:
                q = s_telnet()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 15:
                q = s_smtp()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 16:
                q = s_dns()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 17:
                q = s_http()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 18:
                q = s_pop3()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 19:
                q = s_imap()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 20:
                q = s_snmp()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 21:
                q = s_https()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 22:
                q = s_smb()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 23:
                q = s_smtp_s()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 24:
                q = s_imap_s()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 25:
                q = s_pop3_s()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 26:
                q = s_mysql()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 27:
                q = s_rdp()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 28:
                q = s_oracle()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 29:
                q = s_mssql()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 30:
                q = s_mongodb()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            elif choice == 31:
                q = s_redis()
                if q == "q":
                    print(colored("\nExiting...\n", "red"))
                    break
            else:
                print(colored("Invalid choice! Please enter a valid option.", "red"))
                time.sleep(0.2)
            
        else:
            print(colored("Invalid choice! Please enter a valid option.", "red"))
            time.sleep(0.2)

