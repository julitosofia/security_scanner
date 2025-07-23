from scanner.network_scan import escanear_puertos
from scanner.shodan_lookup import buscar_en_shodan
from scanner.utils import es_ip_privada
from scanner.deep_scan import escaneo_profundo
from rich import print
from rich.prompt import Prompt
from rich.console import Console
from rich.progress import track
from datetime import datetime
import datetime
import time
import os

console= Console()
def limpiar_terminal():
    os.system("cls" if os.name == "nt" else "clear")

def guardar_reporte(ip,resultados):
    timestamp=datetime.datetime.now().strftime("")
    filename=f"output/reporte_{ip}_{timestamp}.txt"
    os.makedirs("output",exist_ok=True)
    with open(filename,"w")as f:
        if es_ip_privada(ip):
            f.write("Advertencia: La IP ingresada es privada. El escaneo puede estar limitado o ser local.\n\n")
        f.write(resultados)
    print(f"\n Reporte guardado: {filename}")

def generar_explicacion(resultados_nmap,resultados_profundo,resultados_shodan):
    explicacion = "\n=== EXPLICACION DE RESULTADOS ===\n"

    if"22/tcp" in resultados_nmap:
        explicacion+= "- El puerto 22 (SSH) esta abierto: puede permitir acceso remoto. Verificar si se usan contraseñas fuertes o claves publicas.\n"
    if "80/tcp" in resultados_nmap:
        explicacion+="- El puerto 80 (HTTP) esta abierto : puede haber servicios web expuestos. Verificar posibbles fallos en la aplicacion.\n"
    if "Apache" in resultados_nmap:
        explicacion+="- Se detecto Apache como servidor web. Verificar version y vulnerabilidades conocidas.\n"
    if "OpenSSH" in resultados_nmap:
        explicacion+="- Se detecto OpenSSH. Chequear si la version es antigua y propensa a vulnerabilidades.\n"
    if "vulners" in resultados_profundo.lower() or "cve" in resultados_profundo.lower():
        explicacion+="- El escaneo encontro vulnerabilidades potenciales. Revisar los CVEs indicados y mitigar.\n"
    if "403" in resultados_shodan:
        explicacion+="- No se pudo acceder a Shodan. Verificar si la API key es valida.\n"
    
    return explicacion


def main():
    limpiar_terminal()
    console.print("""
     _____                 _   _       _____                                  
    / ____|               | | (_)     / ____|                                 
   | (___  _   _ _ __ ___ | |_ _  ___| (___   ___ _ ____   _____ _ __         
    \___ \| | | | '_ ` _ \| __| |/ __|\___ \ / _ \ '__\ \ / / _ \ '__|        
    ____) | |_| | | | | | | |_| | (__ ____) |  __/ |   \ V /  __/ |           
   |_____/ \__, |_| |_| |_|\__|_|\___|_____/ \___|_|    \_/ \___|_|           
            __/ |                                                             
           |___/   "Julian 1.0s"                                                           
    """, style="bold green")

    ip=Prompt.ask("[bold green]Ingresa la IP a escanear[/bold green]")

    resultados_nmap=escanear_puertos(ip)
    resultados_shodan=buscar_en_shodan(ip)
    resultados_profundo=escaneo_profundo(ip)

    explicacion=generar_explicacion(resultados_nmap,resultados_profundo,resultados_shodan)


    reporte_completo=(
        f"Reporte de analisis de IP: {ip}\n\n"
        "=== NMAP ===\n"+resultados_nmap +
        "\n\n=== ESCANEO PROFUNDO ===\n" + resultados_profundo +
        "\n\n=== SHODAN ===\n" + str(resultados_shodan) + 
        "\n\n" + explicacion
    )

    guardar_reporte(ip,reporte_completo)


if __name__=="__main__":
    main()