import psutil
import subprocess
from typing import List, Dict
from pydantic import BaseModel
import ipaddress

class System(BaseModel):
    destination: str
    gateway: str
    genmask: str
    iface: str

def get_network_interfaces() -> Dict[str, List[str]]:
    interfaces = psutil.net_if_addrs()
    return {iface: [addr.address for addr in addresses] for iface, addresses in interfaces.items()}

def get_network_routes() -> List[Dict[str, str]]:
    try:
        result = subprocess.run(['ip', 'route'], capture_output=True, text=True, check=True)
        routes = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                destination = parts[0]
                gateway = parts[2]
                iface = parts[-1]

                if 'dev' in parts:
                    dev_index = parts.index('dev')
                    if dev_index > 0 and '/' in parts[dev_index - 1]:
                        cidr = parts[dev_index - 1].split('/')[-1]
                        genmask = str(ipaddress.IPv4Network(f'0.0.0.0/{cidr}').netmask)
                    else:
                        genmask = "255.255.255.255"  
                else:
                    genmask = "255.255.255.255"  

                route = {
                    "destination": destination,
                    "gateway": gateway,
                    "genmask": genmask,
                    "iface": iface
                }
                routes.append(route)
        return routes
    except subprocess.CalledProcessError as e:
        raise Exception(f"Error fetching routes: {e}")

def add_gateway(interface: System) -> str:
    command = f"ip route add {interface.destination} via {interface.gateway} dev {interface.iface}"
    try:
        subprocess.run(command.split(), check=True)
        return f"Gateway {interface.gateway} added for {interface.destination} on {interface.iface}"
    except subprocess.CalledProcessError as e:
        raise Exception(f"Error adding gateway: {e}")