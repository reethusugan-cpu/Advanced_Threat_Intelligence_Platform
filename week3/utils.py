import socket
from urllib.parse import urlparse


def extract_ip_from_ioc(ioc, ioc_type):

    try:

        ioc_type = ioc_type.lower()

        # Direct IP
        if ioc_type in ["ipv4", "ip"]:
            return ioc

        # URL
        elif ioc_type == "url":

            hostname = urlparse(ioc).hostname

            if hostname:
                return socket.gethostbyname(hostname)

        # Domain
        elif ioc_type in ["domain", "hostname"]:

            return socket.gethostbyname(ioc)

    except:
        return None

    return None