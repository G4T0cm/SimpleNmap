import nmap
import socket
import subprocess
import platform

def get_os_from_ttl(ttl):
    if ttl <= 64:
        return "Linux/Unix"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Cisco"
    else:
        return "Unknown"

def ping_host(host):
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', host]
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)

        for line in output.splitlines():
            if 'ttl=' in line.lower():
                ttl_value = int(line.split('ttl=')[1].split()[0])
                return ttl_value

    except subprocess.CalledProcessError:
        return None

def scan_network(network):
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')

    hosts = []
    for host in nm.all_hosts():
        try:
            host_name = socket.gethostbyaddr(host)[0]
        except socket.herror:
            host_name = 'Unknown'

        ttl = ping_host(host)
        os_guess = get_os_from_ttl(ttl) if ttl is not None else 'Unknown'

        hosts.append({
            'ip': host,
            'name': host_name,
            'ttl': ttl,
            'os': os_guess
        })

    return hosts

def main():
    print("Elige una opcion:")
    print("1. Introducir rango (e.g., 192.168.1.0/24)")
    print("2. Analiza tu propia red")
    
    choice = input("Selecciona opcion: ")

    if choice == '1':
        network = input("Introduce el rango: ")
    elif choice == '2':
        network = '192.168.1.0/24' 
    else:
        print("Eleccion incorrecta")
        return

    hosts = scan_network(network)

    for host in hosts:
        print(f"IP: {host['ip']}, Name: {host['name']}, TTL: {host['ttl']}, OS: {host['os']}")

if __name__ == '__main__':
    main()
