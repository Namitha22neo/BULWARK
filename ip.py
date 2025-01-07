import nmap
from user_agents import parse
import re

# Function to validate an IP address
def validate_ip(ip):
    pattern = re.compile(
        r"^((25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.){3}"
        r"(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$"
    )
    return pattern.match(ip)

# Function to run Nmap and get device info based on IP
def get_device_info_with_nmap(ip):
    nm = nmap.PortScanner()
    try:
        # Perform an OS scan with Nmap
        nm.scan(ip, arguments='-O')
        if ip in nm.all_hosts():
            os_fingerprint = nm[ip]['osmatch'] if 'osmatch' in nm[ip] else "Unknown OS"
            device_info = {
                "IP": ip,
                "Device Name": nm[ip].hostname() if nm[ip].hostname() else "Unknown Device",
                "OS": os_fingerprint,
                "MAC Address": nm[ip]['addresses'].get('mac', "Unknown MAC")
            }
        else:
            device_info = {"error": "IP address not found during scanning"}
        return device_info
    except Exception as e:
        return {"error": str(e)}

# Function to extract device details from User-Agent string
def get_device_details(user_agent_string):
    user_agent = parse(user_agent_string)
    return {
        "Browser": user_agent.browser.family,
        "Browser Version": user_agent.browser.version_string,
        "OS": user_agent.os.family,
        "OS Version": user_agent.os.version_string,
        "Device Type": "Mobile" if user_agent.is_mobile else "Tablet" if user_agent.is_tablet else "PC",
    }

# Consolidated function for both location and device details
def get_ip_and_device_details(ip, user_agent_string=None):
    if not validate_ip(ip):
        return {"error": "Invalid IP address"}
    
    # Fetch dynamic device details with Nmap
    device_details = get_device_info_with_nmap(ip)
    
    if user_agent_string:
        try:
            ua_details = get_device_details(user_agent_string)
            device_details.update(ua_details)
        except Exception as e:
            device_details["Device Error"] = str(e)
    
    return device_details

# Example usage
if __name__ == "__main__":
    # Prompt the user to enter the IP address
    ip = input("Enter the IP address to scan: ")
    user_agent_string = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
    )

    details = get_ip_and_device_details(ip, user_agent_string)
    print(details)
