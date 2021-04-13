import socket
from contextlib import closing
from .ports import ports_tcp, ports_udp
from time import sleep
from .packets import dns_packet, http_packet

##
# Helpers
##

ICMP_PROTO = socket.getprotobyname("icmp")

def udp_scan(target_ip, next_port, limits):
    for i in range(limits["udp_retries"]):
        sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_udp.settimeout(limits["udp_sock_timeout"])
        sock_udp.setsockopt(socket.SOL_IP, socket.IP_TTL, limits["udp_ip_timeout"])
        try:
            sock_udp.sendto(dns_packet(), (target_ip, next_port))
            data, _ = sock_udp.recvfrom(1024)
            sock_udp.close()
            return 2, prep_message(data)
        except socket.timeout:
            pass
        sock_udp.close()
        sleep(limits["udp_retry_delay"])
    return 3, ""

def tcp_scan(target_ip, next_port, limits):
    is_open = False
    for i in range(limits["tcp_retries"]):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(limits["tcp_sock_timeout"])
        sock.setsockopt(socket.SOL_IP, socket.IP_TTL, limits["tcp_ip_timeout"])
        if sock.connect_ex((target_ip, next_port)) == 0:
            is_open = True
            sock.close()
            break
        sleep(limits["tcp_retry_delay"])
        sock.close()
    return is_open

def tcp_message(target_ip, next_port, limits):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(limits["tcp_sock_msg_timeout"])
    sock.setsockopt(socket.SOL_IP, socket.IP_TTL, int(max(limits["tcp_ip_timeout"], limits["tcp_sock_msg_timeout"])))
    if sock.connect_ex((target_ip, next_port)) != 0:
        sock.close()
        return ""
    try:
        message = sock.recv(1024)
        if len(message) > 0:
            sock.close()
            return prep_message(message)
    except:
        pass
    if limits["tcp_msg"]:
        try:
            sock.sendall(http_packet(target_ip))
            message = sock.recv(1024)
            sock.close()
            return prep_message(message)
        except:
            pass
    sock.close()
    return ""

def prep_message(msg):
    try:
        msg = msg.decode()
        if msg == "":
            return msg
        msg = msg.replace("\r\n", "\n").replace("\n\r", "\n")
        parts = msg[:128].split("\n")[:3]
        return "\n".join(msg.split("\n")[:3])
    except:
        return "[Unreadable]"


##
# PortData Class
##

class PortData():

    def __init__(self, target, port):
        self.target = target
        self.port = int(port)
        self.tcp  = 0
        self.tcp_msg = ""
        self.udp  = 0
        self.udp_msg = ""

    def scan(self, limits):
        if limits["tcp"]:
            tcp = tcp_scan(self.target, self.port, limits)
            if tcp:
                self.tcp = 2
                self.tcp_msg = tcp_message(self.target, self.port, limits)
            else:
                self.tcp = 3
        if limits["udp"]:
            self.udp, self.udp_msg = udp_scan(self.target, self.port, limits)

    def tcp_status(self):
        statuses = {
            0: "",
            1: "Testing...",
            2: "Open",
            3: "Closed",
        }
        return statuses[self.tcp]

    def udp_status(self):
        statuses = {
            0: "",
            1: "Testing...",
            2: "Open", # Any response
            3: "Unknown", # No response
            4: "Closed", # ICMP port unreachable (type 3, code 3)
            5: "Filtered", # Other ICMP unreachable (type 3, code not 3)
        }
        return statuses[self.udp]

    def tcp_info(self):
        detected = []
        if "SSH" in self.tcp_msg:
            detected.append("SSH")
        if "FTP" in self.tcp_msg:
            detected.append("FTP")
        if "HTTP" in self.tcp_msg:
            detected.append("HTTP")
        if self.port in ports_tcp:
            return ", ".join(ports_tcp[self.port]+detected)
        return ", ".join(detected)

    def udp_info(self):
        if self.port in ports_udp:
            return ", ".join(ports_udp[self.port])
        return ""
