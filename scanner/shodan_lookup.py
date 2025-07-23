import shodan
import os

def buscar_en_shodan(ip):
    api_key= os.environ.get("SHODAN_API_KEY")
    if not api_key:
        return "Error: SHODAN_API_KEY no esta configurado como variable de entorno."
    api=shodan.Shodan(api_key)
    try:
        host=api.host(ip)
        return host
    except shodan.APIError as e:
        return f"Error:{e}"