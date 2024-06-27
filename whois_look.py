#!/var/ossec/framework/python/bin/python3
# Copyright Whysecurity Cellatica 2024
import json
import sys
import ipaddress
import logging
import requests
from socket import socket, AF_UNIX, SOCK_DGRAM

# Configure the logger for writing to a file
logging.basicConfig(filename='/var/ossec/logs/output.log', level=logging.DEBUG, format='%(asctime)s - %(message)s')

# Create a separate logger for console output
console_logger = logging.getLogger('console')
console_logger.setLevel(logging.INFO)  # Set the level as needed

# Create a handler for console output
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
console_logger.addHandler(console_handler)

# Global variable for the Wazuh socket path
socket_addr = "/var/ossec/queue/sockets/queue"

def send_event(msg, agent=None):
    """
    Sends event data to Wazuh.
    """
    debug("Sending event to Wazuh")
    if not agent or agent["id"] == "000":
        string = "1:whois:{0}".format(json.dumps(msg))
    else:
        string = "1:[{0}] ({1}) {2}->whois:{3}".format(
            agent["id"],
            agent["name"],
            agent["ip"] if "ip" in agent else "any",
            json.dumps(msg),
        )
    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(socket_addr)
        sock.send(string.encode())
        sock.close()
        debug("Message sent to Wazuh socket")
    except Exception as e:
        debug(f"Failed to send message to Wazuh socket: {str(e)}")

def debug(message):
    logging.debug(message)
    console_logger.debug(message)

def is_public_ip(ip):
    try:
        ip_addr = ipaddress.ip_address(ip)
        return not ip_addr.is_private
    except ValueError:
        debug(f"Invalid IP address: {ip}")
        return False

def whois_lookup(ip):
    debug(f"Performing WHOIS lookup for IP: {ip}")
    try:
        url = f"https://rdap.arin.net/registry/ip/{ip}"
        response = requests.get(url)
        if response.status_code == 200:
            whois_data = response.json()

            # Extract owner information
            owner_info = {
                "handle": whois_data.get("handle", ""),
                "startAddress": whois_data.get("startAddress", ""),
                "endAddress": whois_data.get("endAddress", ""),
                "ipVersion": whois_data.get("ipVersion", ""),
                "name": whois_data.get("name", ""),
                "type": whois_data.get("type", ""),
                "country": whois_data.get("country", "")
            }

            debug(f"WHOIS lookup successful for IP: {ip}")
            debug(f"Owner Information for IP {ip}: {owner_info}")

            return owner_info
        else:
            debug(f"WHOIS lookup failed for IP: {ip}. Status code: {response.status_code}")
            return None
    except Exception as e:
        debug(f"WHOIS lookup failed for IP: {ip}. Error: {e}")
        return None

def main(json_path):
    debug(f"Reading JSON data from file: {json_path}")
    try:
        with open(json_path, 'r') as file:
            try:
                data = json.load(file)
                debug("JSON data loaded successfully!")
            except json.JSONDecodeError as json_error:
                debug(f"JSON decoding error: {json_error}")
                return
    except IOError as io_error:
        debug(f"IOError: {io_error}")
        return
    except Exception as e:
        debug(f"Exception occurred while reading JSON file: {e}")
        return

    ip_info = {}

    debug("Extracting IP information from alert data")
    if "_source" in data and "data" in data["_source"]:
        if "srcip" in data["_source"]["data"]:
            ip_info["srcip"] = data["_source"]["data"]["srcip"]
        if "dstip" in data["_source"]["data"]:
            ip_info["dstip"] = data["_source"]["data"]["dstip"]
        if "srcPostNAT" in data["_source"]["data"]:
            ip_info["srcPostNAT"] = data["_source"]["data"]["srcPostNAT"]
    elif "data" in data:
        if "srcip" in data["data"]:
            ip_info["srcip"] = data["data"]["srcip"]
        if "dstip" in data["data"]:
            ip_info["dstip"] = data["data"]["dstip"]
        if "srcPostNAT" in data["data"]:
            ip_info["srcPostNAT"] = data["data"]["srcPostNAT"]
    else:
        debug(f"No data found in JSON path")
        return

    for field, ip in ip_info.items():
        debug(f"Processing {field}: {ip}")
        if is_public_ip(ip):
            debug(f"{ip} is a public IP.")
            whois_result = whois_lookup(ip)
            if whois_result:
                debug(f"WHOIS lookup result for {ip}: DONE!")
                # Format WHOIS information for Wazuh
                msg = {"ip": ip, "whois_info": whois_result}
                send_event(msg)
            else:
                debug(f"Failed to retrieve WHOIS information for {ip}.")
        else:
            debug(f"{ip} is not a public IP.")

if __name__ == "__main__":
    debug(f"Script called with arguments: {sys.argv}")
    if len(sys.argv) < 2:
        console_logger.error("Usage: python script.py <path_to_json>")
        debug("Incorrect number of arguments provided.")
        sys.exit(1)

    json_path = sys.argv[1]  # Corrected typo from sys.args to sys.argv
    debug(f"Script called with JSON path: {json_path}")
    main(json_path)