#!/usr/bin/env python3
"""
Escaner de red defensivo y autorizado basado en Nmap.

Mejoras sobre la version original:
- Arquitectura modular y mantenible.
- Validacion robusta de objetivos (IPv4, IPv6, CIDR y hostnames).
- Soporte para multiples objetivos desde CLI o archivo.
- Perfiles de escaneo con override de argumentos.
- Resultados estructurados con exportacion a TXT, JSON y CSV.
- Logging real con niveles de verbosidad.
- Manejo de errores y codigos de salida consistentes.
- Resumen agregado al finalizar.

Requisitos:
- nmap instalado en el sistema
- python-nmap instalado: pip install python-nmap

Uso etico:
Ejecuta escaneos solo sobre sistemas, redes y activos para los que tengas
autorizacion expresa.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import logging
import shutil
import socket
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

try:
    import nmap  # type: ignore
except ImportError:  # pragma: no cover - depende del entorno del usuario
    nmap = None

LOGGER = logging.getLogger("nmap_scan")
DEFAULT_PROFILE = "equilibrado"
DEFAULT_TIMEOUT = 900

PROFILES: dict[str, str] = {
    # Mantengo perfiles utiles para administracion autorizada.
    "rapido": "-Pn -T4 -F",
    "equilibrado": "-Pn -sV -sC -T4",
    "completo": "-Pn -sV -sC -O -T4 -p-",
    "servicios": "-Pn -sV --version-light -T4",
    "inventario": "-Pn -O --traceroute",
}


@dataclass(slots=True)
class PortInfo:
    port: int
    protocol: str
    state: str
    service: str
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    reason: str = ""
    cpe: list[str] = field(default_factory=list)
    scripts: dict[str, Any] = field(default_factory=dict)

    @property
    def banner(self) -> str:
        parts = [self.product.strip(), self.version.strip(), self.extrainfo.strip()]
        value = " ".join(part for part in parts if part)
        return value or "No detectada"


@dataclass(slots=True)
class HostResult:
    target: str
    resolved_address: str = ""
    state: str = "unknown"
    hostnames: list[str] = field(default_factory=list)
    addresses: dict[str, str] = field(default_factory=dict)
    vendor: dict[str, str] = field(default_factory=dict)
    uptime: dict[str, Any] = field(default_factory=dict)
    os_matches: list[dict[str, Any]] = field(default_factory=list)
    ports: list[PortInfo] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    raw_nmap: dict[str, Any] = field(default_factory=dict)

    @property
    def open_ports(self) -> list[PortInfo]:
        return [port for port in self.ports if port.state == "open"]


@dataclass(slots=True)
class ScanResult:
    started_at: str
    finished_at: str
    duration_seconds: float
    profile: str
    arguments: str
    scanner_version: str
    targets: list[str]
    hosts: list[HostResult]
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def total_hosts(self) -> int:
        return len(self.hosts)

    @property
    def total_open_ports(self) -> int:
        return sum(len(host.open_ports) for host in self.hosts)


class ScanError(Exception):
    """Error controlado del escaner."""


class TargetValidationError(ScanError):
    """Objetivo invalido o no resoluble."""



def configure_logging(verbose: int) -> None:
    level = logging.WARNING
    if verbose == 1:
        level = logging.INFO
    elif verbose >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="[%(levelname)s] %(message)s")



def ensure_environment() -> None:
    if nmap is None:
        raise ScanError(
            "No se pudo importar python-nmap. Instala la dependencia con: pip install python-nmap"
        )

    if shutil.which("nmap") is None:
        raise ScanError(
            "No se encontro el binario 'nmap' en el PATH. Instala Nmap y vuelve a intentarlo."
        )

    try:
        scanner = nmap.PortScanner()
        LOGGER.debug("Version de Nmap detectada por python-nmap: %s", scanner.nmap_version())
    except Exception as exc:  # pragma: no cover - depende del entorno del usuario
        raise ScanError(f"Nmap parece instalado, pero no pudo inicializarse correctamente: {exc}") from exc



def unique_preserve_order(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        cleaned = item.strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            result.append(cleaned)
    return result



def load_targets_from_file(path: Path) -> list[str]:
    if not path.exists():
        raise TargetValidationError(f"El archivo de objetivos no existe: {path}")
    if not path.is_file():
        raise TargetValidationError(f"La ruta indicada no es un archivo: {path}")

    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    targets = [line.split("#", 1)[0].strip() for line in lines]
    targets = [item for item in targets if item]
    if not targets:
        raise TargetValidationError(f"El archivo de objetivos esta vacio: {path}")
    return unique_preserve_order(targets)



def validate_target(target: str) -> str:
    candidate = target.strip()
    if not candidate:
        raise TargetValidationError("Se recibio un objetivo vacio.")

    # IP individual o red CIDR.
    try:
        if "/" in candidate:
            ipaddress.ip_network(candidate, strict=False)
            return candidate
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        pass

    # Hostname resoluble.
    try:
        socket.getaddrinfo(candidate, None)
        return candidate
    except socket.gaierror as exc:
        raise TargetValidationError(f"No se pudo resolver el objetivo '{candidate}'.") from exc



def collect_targets(cli_targets: list[str], targets_file: Optional[str]) -> list[str]:
    targets: list[str] = list(cli_targets)
    if targets_file:
        targets.extend(load_targets_from_file(Path(targets_file)))

    targets = unique_preserve_order(targets)
    if not targets:
        raise TargetValidationError("Debes indicar al menos un objetivo o un archivo con objetivos.")

    validated = [validate_target(target) for target in targets]
    return validated



def build_arguments(profile: str, custom_arguments: Optional[str]) -> str:
    if profile not in PROFILES:
        valid = ", ".join(sorted(PROFILES))
        raise ScanError(f"Perfil no valido '{profile}'. Perfiles disponibles: {valid}")
    if custom_arguments and custom_arguments.strip():
        return custom_arguments.strip()
    return PROFILES[profile]



def create_scanner() -> Any:
    assert nmap is not None
    return nmap.PortScanner()



def parse_host(scanner: Any, requested_target: str, host_key: str) -> HostResult:
    host_data = scanner[host_key]
    hostnames = [entry.get("name", "") for entry in host_data.get("hostnames", []) if entry.get("name")]
    addresses = dict(host_data.get("addresses", {}))
    vendor = dict(host_data.get("vendor", {}))
    os_matches = list(host_data.get("osmatch", []))
    uptime = dict(host_data.get("uptime", {}))
    warnings: list[str] = []

    if not host_data.get("tcp") and not host_data.get("udp"):
        warnings.append("El host no expuso puertos TCP/UDP en los resultados devueltos.")

    ports: list[PortInfo] = []
    for protocol in sorted(host_data.all_protocols()):
        for port_number, info in sorted(host_data[protocol].items()):
            if not isinstance(info, dict):
                continue
            scripts = info.get("script", {})
            ports.append(
                PortInfo(
                    port=int(port_number),
                    protocol=protocol,
                    state=str(info.get("state", "unknown")),
                    service=str(info.get("name", "desconocido")),
                    product=str(info.get("product", "")),
                    version=str(info.get("version", "")),
                    extrainfo=str(info.get("extrainfo", "")),
                    reason=str(info.get("reason", "")),
                    cpe=list(info.get("cpe", [])) if isinstance(info.get("cpe"), list) else [],
                    scripts=dict(scripts) if isinstance(scripts, dict) else {},
                )
            )

    return HostResult(
        target=requested_target,
        resolved_address=host_key,
        state=str(host_data.state()),
        hostnames=hostnames,
        addresses=addresses,
        vendor=vendor,
        uptime=uptime,
        os_matches=os_matches,
        ports=ports,
        warnings=warnings,
        raw_nmap=dict(host_data),
    )



def run_scan(targets: list[str], arguments: str, timeout: int) -> ScanResult:
    scanner = create_scanner()
    started = datetime.now(timezone.utc)
    LOGGER.info("Iniciando escaneo de %d objetivo(s)", len(targets))
    LOGGER.debug("Objetivos: %s", ", ".join(targets))
    LOGGER.debug("Argumentos Nmap: %s", arguments)

    t0 = time.perf_counter()
    try:
        scan_output = scanner.scan(hosts=" ".join(targets), arguments=arguments, timeout=timeout)
    except nmap.PortScannerTimeout as exc:
        raise ScanError(f"El escaneo excedio el timeout configurado ({timeout}s).") from exc
    except nmap.PortScannerError as exc:
        raise ScanError(f"Nmap devolvio un error: {exc}") from exc
    except Exception as exc:
        raise ScanError(f"Fallo inesperado al ejecutar el escaneo: {exc}") from exc
    duration = time.perf_counter() - t0
    finished = datetime.now(timezone.utc)

    found_hosts = scanner.all_hosts()
    LOGGER.info("Escaneo finalizado. Hosts detectados: %d", len(found_hosts))

    host_results: list[HostResult] = []
    global_warnings: list[str] = []
    errors: list[str] = []

    target_to_hostkeys: dict[str, list[str]] = {target: [] for target in targets}
    for host_key in found_hosts:
        if host_key in targets:
            target_to_hostkeys.setdefault(host_key, []).append(host_key)
            continue

        # Intento razonable de asociar host resuelto con objetivo original.
        matched_target = None
        for target in targets:
            if target == host_key:
                matched_target = target
                break
            try:
                infos = socket.getaddrinfo(target, None)
                resolved_addresses = {item[4][0] for item in infos if item and len(item) >= 5}
                if host_key in resolved_addresses:
                    matched_target = target
                    break
            except socket.gaierror:
                continue
        target_to_hostkeys.setdefault(matched_target or host_key, []).append(host_key)

    for requested_target in targets:
        host_keys = target_to_hostkeys.get(requested_target, [])
        if not host_keys:
            errors.append(f"No se devolvieron resultados para el objetivo: {requested_target}")
            host_results.append(
                HostResult(
                    target=requested_target,
                    state="no-result",
                    warnings=["Nmap no devolvio hosts asociados a este objetivo."],
                )
            )
            continue

        for host_key in host_keys:
            try:
                host_results.append(parse_host(scanner, requested_target, host_key))
            except Exception as exc:
                LOGGER.exception("Error parseando host %s", host_key)
                errors.append(f"No se pudo procesar el host {host_key}: {exc}")

    scaninfo = scan_output.get("nmap", {}).get("scaninfo", {}) if isinstance(scan_output, dict) else {}
    if not scaninfo:
        global_warnings.append("Nmap no devolvio metadatos detallados de scaninfo.")

    version = scanner.nmap_version()
    version_text = ".".join(map(str, version)) if isinstance(version, tuple) else str(version)

    return ScanResult(
        started_at=started.isoformat(),
        finished_at=finished.isoformat(),
        duration_seconds=duration,
        profile="custom",
        arguments=arguments,
        scanner_version=version_text,
        targets=targets,
        hosts=host_results,
        warnings=global_warnings,
        errors=errors,
    )



def render_console(result: ScanResult) -> str:
    lines: list[str] = []
    lines.append("=" * 80)
    lines.append("ESCANEO NMAP - RESUMEN")
    lines.append("=" * 80)
    lines.append(f"Inicio (UTC):      {result.started_at}")
    lines.append(f"Fin (UTC):         {result.finished_at}")
    lines.append(f"Duracion:          {result.duration_seconds:.2f}s")
    lines.append(f"Version Nmap:      {result.scanner_version}")
    lines.append(f"Argumentos:        {result.arguments}")
    lines.append(f"Objetivos:         {', '.join(result.targets)}")
    lines.append(f"Hosts procesados:  {result.total_hosts}")
    lines.append(f"Puertos abiertos:  {result.total_open_ports}")

    for warning in result.warnings:
        lines.append(f"ADVERTENCIA: {warning}")
    for error in result.errors:
        lines.append(f"ERROR: {error}")

    lines.append("")
    for index, host in enumerate(result.hosts, start=1):
        lines.append("-" * 80)
        lines.append(f"HOST #{index}: {host.target}")
        lines.append(f"Direccion resuelta: {host.resolved_address or 'N/D'}")
        lines.append(f"Estado:             {host.state}")
        if host.hostnames:
            lines.append(f"Hostnames:          {', '.join(host.hostnames)}")
        if host.addresses:
            lines.append(
                "Direcciones:        " + ", ".join(f"{k}={v}" for k, v in sorted(host.addresses.items()))
            )
        if host.vendor:
            lines.append("Vendor MAC:         " + ", ".join(f"{k}: {v}" for k, v in host.vendor.items()))
        if host.uptime:
            lines.append("Uptime:             " + ", ".join(f"{k}={v}" for k, v in host.uptime.items()))
        if host.os_matches:
            top_os = host.os_matches[:3]
            os_desc = "; ".join(
                f"{item.get('name', 'Desconocido')} ({item.get('accuracy', '?')}%)" for item in top_os
            )
            lines.append(f"SO probable:        {os_desc}")
        for warning in host.warnings:
            lines.append(f"Advertencia host:   {warning}")

        if not host.ports:
            lines.append("Puertos:            Sin datos")
            continue

        lines.append("")
        lines.append(f"{'PROTO':<8}{'PUERTO':<8}{'ESTADO':<10}{'SERVICIO':<18}VERSION")
        lines.append("~" * 80)
        for port in sorted(host.ports, key=lambda item: (item.protocol, item.port)):
            lines.append(
                f"{port.protocol:<8}{port.port:<8}{port.state:<10}{port.service:<18}{port.banner}"
            )
            if port.scripts:
                for script_name, script_output in port.scripts.items():
                    normalized = str(script_output).strip().replace("\n", " | ")
                    lines.append(f"    script:{script_name}: {normalized}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"



def result_to_dict(result: ScanResult) -> dict[str, Any]:
    return asdict(result)



def save_json(result: ScanResult, output_path: Path) -> None:
    output_path.write_text(json.dumps(result_to_dict(result), indent=2, ensure_ascii=False), encoding="utf-8")



def save_txt(result: ScanResult, output_path: Path) -> None:
    output_path.write_text(render_console(result), encoding="utf-8")



def save_csv(result: ScanResult, output_path: Path) -> None:
    with output_path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(
            [
                "target",
                "resolved_address",
                "state",
                "protocol",
                "port",
                "service",
                "banner",
                "reason",
                "hostnames",
            ]
        )
        for host in result.hosts:
            if not host.ports:
                writer.writerow(
                    [
                        host.target,
                        host.resolved_address,
                        host.state,
                        "",
                        "",
                        "",
                        "",
                        "",
                        ";".join(host.hostnames),
                    ]
                )
                continue
            for port in host.ports:
                writer.writerow(
                    [
                        host.target,
                        host.resolved_address,
                        host.state,
                        port.protocol,
                        port.port,
                        port.service,
                        port.banner,
                        port.reason,
                        ";".join(host.hostnames),
                    ]
                )



def save_result(result: ScanResult, output: Optional[str], output_format: str) -> Optional[Path]:
    if not output:
        return None

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fmt = output_format.lower()

    if fmt == "auto":
        suffix = output_path.suffix.lower().lstrip(".")
        fmt = suffix if suffix in {"txt", "json", "csv"} else "txt"

    if fmt == "json":
        save_json(result, output_path)
    elif fmt == "csv":
        save_csv(result, output_path)
    elif fmt == "txt":
        save_txt(result, output_path)
    else:
        raise ScanError(f"Formato de salida no soportado: {output_format}")

    return output_path



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Escaner defensivo/autorizado con Nmap y salida estructurada.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  %(prog)s 192.168.1.10\n"
            "  %(prog)s 192.168.1.10 192.168.1.11 --profile rapido\n"
            "  %(prog)s ejemplo.com -a \"-Pn -sV -p 1-1024\" -o resultado.json --format json\n"
            "  %(prog)s --targets-file objetivos.txt -o resultados.csv --format csv\n"
        ),
    )

    parser.add_argument(
        "targets",
        nargs="*",
        help="Uno o mas objetivos: IP, IPv6, hostname o red CIDR.",
    )
    parser.add_argument(
        "-f",
        "--targets-file",
        help="Archivo con objetivos, uno por linea. Soporta comentarios con #.",
    )
    parser.add_argument(
        "-p",
        "--profile",
        default=DEFAULT_PROFILE,
        choices=sorted(PROFILES),
        help="Perfil de escaneo predefinido.",
    )
    parser.add_argument(
        "-a",
        "--arguments",
        help="Argumentos personalizados para Nmap. Si se indican, reemplazan el perfil.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Ruta de salida para guardar resultados.",
    )
    parser.add_argument(
        "--format",
        default="auto",
        choices=["auto", "txt", "json", "csv"],
        help="Formato de salida. Con auto se infiere por extension cuando sea posible.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Timeout maximo del escaneo en segundos (default: {DEFAULT_TIMEOUT}).",
    )
    parser.add_argument(
        "--show-profiles",
        action="store_true",
        help="Muestra los perfiles disponibles y sale.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Aumenta la verbosidad (-v o -vv).",
    )
    return parser



def print_profiles() -> None:
    print("Perfiles disponibles:\n")
    for name, args in sorted(PROFILES.items()):
        print(f"- {name:<11} {args}")



def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.verbose)

    if args.show_profiles:
        print_profiles()
        return 0

    try:
        ensure_environment()
        targets = collect_targets(args.targets, args.targets_file)
        nmap_arguments = build_arguments(args.profile, args.arguments)
        result = run_scan(targets=targets, arguments=nmap_arguments, timeout=args.timeout)
        result.profile = args.profile if not args.arguments else "custom"

        console_output = render_console(result)
        print(console_output, end="")

        output_path = save_result(result, args.output, args.format)
        if output_path:
            print(f"\n[+] Resultados guardados en: {output_path}")

        # 0 = sin errores parseados ni fallos parciales, 2 = parcial.
        return 2 if result.errors else 0
    except KeyboardInterrupt:
        LOGGER.error("Escaneo cancelado por el usuario.")
        return 130
    except ScanError as exc:
        LOGGER.error("%s", exc)
        return 1
    except Exception as exc:  # pragma: no cover - ultima barrera defensiva
        LOGGER.exception("Error no controlado")
        print(f"Error no controlado: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
