#!/usr/bin/env python3
"""
Script para realizar un escaneo completo con Nmap desde Python
Autor: Asistente
Requisitos: pip install python-nmap
"""

import nmap
import sys
import argparse
import time
from datetime import datetime

def escaneo_completo(ip, argumentos="-sS -sV -sC -O -T4 -p-"):
    """
    Realiza un escaneo completo a una IP específica
    
    Args:
        ip (str): Dirección IP a escanear
        argumentos (str): Argumentos de Nmap a utilizar
    
    Returns:
        dict: Resultados del escaneo
    """
    try:
        # Crear objeto scanner
        scanner = nmap.PortScanner()
        
        print(f"\n{'='*60}")
        print(f"Iniciando escaneo completo a: {ip}")
        print(f"Argumentos Nmap: {argumentos}")
        print(f"Fecha/Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")
        
        # Realizar escaneo
        print("Escaneando... Esto puede tomar varios minutos...")
        inicio = time.time()
        
        # Ejecutar escaneo
        scanner.scan(ip, arguments=argumentos)
        
        fin = time.time()
        tiempo_total = fin - inicio
        
        # Mostrar resultados
        print_resultados(scanner, ip, tiempo_total)
        
        return scanner
        
    except nmap.PortScannerError as e:
        print(f"Error en Nmap: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error inesperado: {e}")
        sys.exit(1)

def print_resultados(scanner, ip, tiempo_total):
    """Imprime los resultados del escaneo de forma organizada"""
    
    if ip not in scanner.all_hosts():
        print(f"No se encontró información para la IP: {ip}")
        return
    
    print(f"\n{'='*60}")
    print(f"RESULTADOS DEL ESCANEO")
    print(f"{'='*60}")
    print(f"IP Escaneada: {ip}")
    print(f"Estado del host: {scanner[ip].state()}")
    print(f"Tiempo total: {tiempo_total:.2f} segundos")
    
    # Información del sistema operativo
    if 'osmatch' in scanner[ip]:
        print(f"\n--- SISTEMA OPERATIVO ---")
        for os in scanner[ip]['osmatch']:
            print(f"  {os['name']} (Precisión: {os['accuracy']}%)")
    
    # Puertos abiertos
    if 'tcp' in scanner[ip]:
        puertos_abiertos = []
        for puerto in scanner[ip]['tcp']:
            if scanner[ip]['tcp'][puerto]['state'] == 'open':
                puertos_abiertos.append(puerto)
        
        if puertos_abiertos:
            print(f"\n--- PUERTOS ABIERTOS ({len(puertos_abiertos)} totales) ---")
            print(f"{'PUERTO':<10} {'ESTADO':<12} {'SERVICIO':<15} {'VERSIÓN'}")
            print("-" * 70)
            
            for puerto in sorted(puertos_abiertos):
                info = scanner[ip]['tcp'][puerto]
                nombre_servicio = info.get('name', 'desconocido')
                version = info.get('version', '')
                product = info.get('product', '')
                extrainfo = info.get('extrainfo', '')
                
                version_completa = f"{product} {version} {extrainfo}".strip()
                if not version_completa:
                    version_completa = "No detectada"
                
                print(f"{puerto:<10} {info['state']:<12} {nombre_servicio:<15} {version_completa}")
        else:
            print("\n--- No se encontraron puertos abiertos ---")
    
    print(f"\n{'='*60}")

def escaneo_guardar_resultados(ip, archivo_salida=None, argumentos="-sS -sV -sC -O -T4 -p-"):
    """
    Realiza escaneo y opcionalmente guarda los resultados en archivo
    """
    scanner = escaneo_completo(ip, argumentos)

    if archivo_salida:
        try:
            with open(archivo_salida, 'w', encoding='utf-8') as f:
                f.write(f"Resultados del escaneo a {ip}\n")
                f.write(f"Fecha: {datetime.now()}\n")
                f.write(f"{'='*60}\n\n")

                if ip in scanner.all_hosts():
                    f.write(f"Estado: {scanner[ip].state()}\n\n")

                    if 'tcp' in scanner[ip]:
                        f.write("Puertos abiertos:\n")
                        for puerto in sorted(scanner[ip]['tcp']):
                            info = scanner[ip]['tcp'][puerto]
                            if info['state'] == 'open':
                                nombre = info.get('name', 'desconocido')
                                product = info.get('product', '')
                                version = info.get('version', '')
                                extrainfo = info.get('extrainfo', '')
                                version_completa = f"{product} {version} {extrainfo}".strip() or "No detectada"
                                f.write(f"  {puerto}: {nombre} - {version_completa}\n")

            print(f"\nResultados guardados en: {archivo_salida}")
        except Exception as e:
            print(f"Error al guardar archivo: {e}")

def main():
    """Función principal con argumentos de línea de comandos"""
    
    parser = argparse.ArgumentParser(
        description="Script para realizar escaneos completos con Nmap",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  %(prog)s 192.168.1.1
  %(prog)s 192.168.1.1 -o resultados.txt
  %(prog)s 192.168.1.1 -a "-sT -sV -p 1-1000"
        """
    )
    
    parser.add_argument(
        "ip",
        help="Dirección IP a escanear"
    )
    
    parser.add_argument(
        "-a", "--argumentos",
        default="-sS -sV -sC -O -T4 -p-",
        help="Argumentos de Nmap (default: -sS -sV -sC -O -T4 -p-)"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Archivo para guardar los resultados"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Modo verbose"
    )
    
    args = parser.parse_args()
    
    print("""
    ╔══════════════════════════════════════════════════╗
    ║     Escáner de Puertos con Python y Nmap         ║
    ║           Escaneo Completo a una IP              ║
    ╚══════════════════════════════════════════════════╝
    """)
    
    # Verificar que la IP sea válida
    try:
        # Validación simple de IP
        octetos = args.ip.split('.')
        if len(octetos) != 4:
            print("Error: IP no válida")
            sys.exit(1)
        for octeto in octetos:
            if not 0 <= int(octeto) <= 255:
                print("Error: IP no válida")
                sys.exit(1)
    except ValueError:
        print("Error: Formato de IP no válido")
        sys.exit(1)
    
    # Realizar escaneo
    if args.output:
        escaneo_guardar_resultados(args.ip, args.output)
    else:
        escaneo_completo(args.ip, args.argumentos)

if __name__ == "__main__":
    main()