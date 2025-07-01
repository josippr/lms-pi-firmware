from fritzconnection import FritzConnection
from dotenv import load_dotenv
import os

load_dotenv()

FRITZ_IP = os.getenv("FRITZ_IP")
FRITZ_USERNAME = os.getenv("FRITZ_USERNAME")        
FRITZ_PASSWORD = os.getenv("FRITZ_PASSWORD")

def list_connected_devices(fritz_ip=FRITZ_IP, username=FRITZ_USERNAME, password=FRITZ_PASSWORD):
    try:
        fc = FritzConnection(address=fritz_ip, user=username, password=password)
        devices = fc.call_action('Hosts', 'GetHostNumberOfEntries')['NewHostNumberOfEntries']
        print(f"Total devices found: {devices}")
        for index in range(devices):
            device_info = fc.call_action('Hosts', 'GetGenericHostEntry', NewIndex=index)
            active = device_info.get('NewActive', False)
            if active:
                print(f"\nDevice #{index+1}")
                print(f"  Name      : {device_info.get('NewHostName')}")
                print(f"  IP Address: {device_info.get('NewIPAddress')}")
                print(f"  MAC       : {device_info.get('NewMACAddress')}")
                print(f"  Active    : {active}")
    except Exception as e:
        print(f"Error: {e}")

list_connected_devices(FRITZ_IP, FRITZ_USERNAME, FRITZ_PASSWORD)