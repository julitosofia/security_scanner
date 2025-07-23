import subprocess
import datetime
def escaneo_profundo(ip):
    print("\n Ejecutando escaneo profundo con Nmap...")
    timestamp=datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_file=f"output/deep_scan_{ip}_{timestamp}.txt"

    try:
        comando=[
            "nmap",
            "-O",
            "-sV",
            "--script","vuln",
            ip
        ]
        resultado=subprocess.run(comando,capture_output=True,text=True)
        with open(output_file,"w") as f:
            f.write(resultado.stdout)
        
        print("Escaneo profundo completado")
        return resultado.stdout
    except Exception as e:
        return f"Error ejecutando escaneo profundo: {e}"

