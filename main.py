from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from typing import Any


def run_nmap(target: str) -> str:
    """
    Ejecuta Nmap y devuelve la salida XML como texto.
    Requiere que 'nmap' esté instalado en el sistema.
    """
    cmd = [
        "nmap",
        "-Pn",
        "-sT",
        "-sV",
        "-T4",
        "-oX",
        "-",
        target,
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Nmap devolvió código {result.returncode}.\nSTDERR:\n{result.stderr}"
        )

    return result.stdout


def parse_nmap_xml(xml_text: str) -> list[dict[str, Any]]:
    """
    Extrae hosts, direcciones IP y puertos abiertos con información de servicio.
    """
    root = ET.fromstring(xml_text)
    parsed_hosts: list[dict[str, Any]] = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        address = host.find("address")
        ip = address.get("addr") if address is not None else "unknown"

        host_data: dict[str, Any] = {
            "ip": ip,
            "ports": [],
        }

        ports_node = host.find("ports")
        if ports_node is not None:
            for port in ports_node.findall("port"):
                state_node = port.find("state")
                if state_node is None or state_node.get("state") != "open":
                    continue

                service_node = port.find("service")

                port_info = {
                    "port": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "service": service_node.get("name") if service_node is not None else None,
                    "product": service_node.get("product") if service_node is not None else None,
                    "version": service_node.get("version") if service_node is not None else None,
                    "extra": service_node.get("extrainfo") if service_node is not None else None,
                }

                host_data["ports"].append(port_info)

        parsed_hosts.append(host_data)

    return parsed_hosts


def print_clean_report(hosts: list[dict[str, Any]]) -> None:
    if not hosts:
        print("No se encontraron hosts activos o puertos abiertos.")
        return

    for host in hosts:
        print(f"\nHost: {host['ip']}")
        print("-" * 50)

        if not host["ports"]:
            print("Sin puertos abiertos detectados.")
            continue

        for p in host["ports"]:
            service_label = p["service"] or "unknown"
            details = " ".join(
                x for x in [p["product"], p["version"], p["extra"]] if x
            ).strip()

            line = f"{p['port']}/{p['protocol']}  {service_label}"
            if details:
                line += f"  |  {details}"

            print(line)


if __name__ == "__main__":
    target = "192.168.1.10"
    xml_output = run_nmap(target)
    hosts = parse_nmap_xml(xml_output)
    print_clean_report(hosts)