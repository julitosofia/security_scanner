# scanner/network_scan.py
import subprocess

def escanear_puertos(ip):
    resultado = subprocess.run(["nmap", "-sV", "-Pn", ip], capture_output=True, text=True)
    return resultado.stdout
