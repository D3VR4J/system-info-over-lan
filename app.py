from flask import Flask, render_template, redirect
import platform
import socket
import psutil
from scapy.all import ARP, Ether, srp
import requests
import netifaces, time
import threading


app = Flask(__name__)

def get_system_info():
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    network_info = get_network_info()

    system_info = {
        "Operating System": platform.platform(),
        "Processor": platform.processor(),
        "System Architecture": platform.architecture(),
        "Python Version": platform.python_version(),
        "Machine": platform.machine(),
        "Node": platform.node(),
        "Release": platform.release(),
        "System": platform.system(),
        "Version": platform.version(),
        "Processor Name": platform.processor(),
        "Memory": {
            "Total": memory.total,
            "Available": memory.available,
            "Used": memory.used,
            "Free": memory.free
        },
        "Disk": {
            "Total": disk.total,
            "Used": disk.used,
            "Free": disk.free
        },
        "Network": network_info
    }
    return system_info

def get_system_name(ip_address):
    try:
        system_name = socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        system_name = "Unknown"
    return system_name

def get_vendor_info(mac_address):
    url = f'https://api.maclookup.app/v2/macs/{mac_address}'
    try:
        response = requests.get(url)
        if response.status_code == 200:
            vendor = response.json().get('company')
            if vendor:
                return vendor
            else:
                vendor = "Vendor not found"
                return vendor
    except Exception as e:
        vendor = f"Error: {e}"
        return vendor
    
def get_network_info():
    network_info = {}
    try:
        interfaces = netifaces.interfaces()
        for interface in interfaces:
            addresses = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addresses:
                ipv4_info = addresses[netifaces.AF_INET][0]
                if 'addr' in ipv4_info:
                    network_info['IPv4 Address'] = ipv4_info['addr']
                    network_info['Subnet Mask'] = ipv4_info['netmask']
                    if 'broadcast' in ipv4_info:
                        network_info['Broadcast Address'] = ipv4_info['broadcast']
            if netifaces.AF_INET6 in addresses:
                ipv6_info = addresses[netifaces.AF_INET6][0]
                if 'addr' in ipv6_info:
                    network_info['IPv6 Address'] = ipv6_info['addr']
                    if 'scopeid' in ipv6_info:
                        network_info['Scope ID'] = ipv6_info['scopeid']
            if netifaces.AF_LINK in addresses:
                mac_address = addresses[netifaces.AF_LINK][0]['addr']
                network_info['MAC Address'] = mac_address
    except Exception as e:
        network_info = {"Error": str(e)}
    return network_info

def scan_port(ip, port, open_ports, lock):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Adjust timeout as needed
        result = sock.connect_ex((ip, port))
        if result == 0:
            with lock:
                open_ports.append(port)
            #print(f"Port {port} is open")
        sock.close()
    except socket.error:
        pass

def scan_ports(ip):
    open_ports = []
    lock = threading.Lock()
    threads = []
    for port in range(1, 5000):  # Adjust the port range as needed
        thread = threading.Thread(target=scan_port, args=(ip, port, open_ports, lock))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    return open_ports


def scan_network(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=False, iface_hint=False, retry=1)[0]

    hosts = []
    for sent, received in result:
        system_name = get_system_name(received.psrc)
        system_info = get_system_info()
        mac_address = received.hwsrc
        network_info = get_network_info()
        vendor = get_vendor_info(mac_address)
        ports = scan_ports(received.psrc)
        hosts.append({'ip': received.psrc, 'mac_address': mac_address, 'system_name': system_name, 'system_info': system_info, 'vendor':vendor, 'network_info': network_info, 'open_ports':ports})
    return hosts



@app.route('/')
def reditectt():
    return redirect('/range=24')


@app.route('/range=<int:range>', methods=['GET'])
def network_scan(range):
    default = socket.gethostbyname(socket.gethostname())
    ip_range = f"{default}/{range}"  # Adjust the IP range according to your LAN
    start_time = time.time()
    hosts = scan_network(ip_range)
    end_time = time.time()
    total_time = round(end_time - start_time, 2)
    counter = 0
    
    counter= (len(hosts))
    #return str(hosts)
    return render_template('index.html', hosts=hosts, total_time=total_time, counter = counter)

if __name__ == '__main__':
    app.run(debug=True)
