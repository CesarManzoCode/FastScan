import nmap

# Crear el objeto escáner
nm = nmap.PortScanner()

# Escaneo simple de puertos
resultado = nm.scan('192.168.1.1', '22-443')
print(f"Host: {resultado['nmap']['scaninfo']}")

# Escaneo más detallado
resultado = nm.scan('192.168.1.1', arguments='-sV -sC -O')

# Obtener información del host
for host in nm.all_hosts():
    print(f"\nHost: {host} - Estado: {nm[host].state()}")
    
    # Puertos abiertos
    for proto in nm[host].all_protocols():
        print(f"Protocolo: {proto}")
        ports = nm[host][proto].keys()
        for port in ports:
            print(f"Puerto {port}: {nm[host][proto][port]['state']}")