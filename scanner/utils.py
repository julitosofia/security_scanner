import ipaddress

def es_ip_privada(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
    