from struct import pack
from random import randint

def dns_packet():
    # Simple record request for www.example.com
    packet = pack(">H", randint(0, 65535)) # ID
    packet += pack(">H", 0x0100) # Flags
    packet += pack(">H", 1) # Q
    packet += pack(">H", 0) # A
    packet += pack(">H", 0) # Auth
    packet += pack(">H", 0) # Add
    url = ["www", "example", "com"]
    for part in url:
        packet += pack("B", len(part))
        for s in part:
            packet += pack('c',s.encode())
    packet += pack("B", 0)
    packet += pack(">H", 1) # Type
    packet += pack(">H", 1) # Class
    return bytes(packet)

MOZ = "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0"
CURL = "curl/7.68.0"

def http_packet(host):
    msg = "GET /index.html HTTP/1.1\r\n"
    msg += f"Host: {host}\r\n"
    msg += f"User-Agent: {CURL}\r\n"
    msg += "Accept: */*\r\n\r\n"
    return msg.encode("utf-8")
