import pyfiglet
import shutil
from termcolor import colored
import colorama
from python_modules import check_host_status
from python_modules import autonomous_system_number
from python_modules import dns_lookup
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
    "Scan vulnerable Redis", "Scan vulnerable PostgreSQL"
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
    print(colored(autonomous_system_number.help(),"yellow"))

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
        else:
            print(colored("Invalid choice! Please enter a valid option.", "red"))
            time.sleep(0.2)
