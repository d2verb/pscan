import threading
import socket
from random import randint
from collections import defaultdict

from pscan.protocol import *

class PortScanner:
    def __init__(self, targetip="127.0.0.1", port=80):
        if isinstance(port, int):
            self.ports = [port]
        else:
            self.ports = port

        try:
            self.myip = socket.gethostbyname(socket.gethostname())
            if targetip == "127.0.0.1":
                targetip = self.myip
        except:
            self.myip = "127.0.0.1"

        self.targetip = targetip
        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.scanned = defaultdict(lambda: False)
        self.sport = 49152
    
    def scan(self):
        print(f"Scanning {self.targetip}...")

        recv_thread = threading.Thread(target=self.packet_recv)
        recv_thread.setDaemon(True)
        recv_thread.start()

        send_thread = threading.Thread(target=self.packet_send)
        send_thread.setDaemon(True)
        send_thread.start()

        send_thread.join(5)
        recv_thread.join(5)

    def packet_send(self):
        for port in self.ports:
            # send SYN packet
            self.send(self.sport, port, "S")
            self.sport += 1

    def packet_recv(self):
        n_ports = len(self.ports)
        while n_ports != 0:
            data = self.recv_sock.recv(65565)

            ip = IP.load(data[:IP.size()])
            tcp = TCP.load(data[IP.size():IP.size()+TCP.size()])

            if ip.src != self.targetip or ip.dst != self.myip:
                continue

            if tcp.dport < 49152 or tcp.flags != "SA":
                continue

            if self.scanned[tcp.sport]:
                continue

            # received SYN-ACK packet
            self.dump_status(tcp.sport, "open")

            n_ports -= 1
            self.scanned[tcp.sport] = True

            # send RST packet
            self.send(tcp.dport, tcp.sport, "R")

    def send(self, sport, dport, flags):
        head = TCP(sport=sport, dport=dport, flags=flags)
        head.update_chksum(saddr=self.myip, daddr=self.targetip)
        self.send_sock.sendto(head.bytes(), (self.targetip, dport))

    def dump_status(self, port, status):
        try:
            service_name = socket.getservbyport(port, "tcp")
        except OSError:
            service_name = "unknown"

        port_info = f"{port:5}/{service_name}"
        print(f"{port_info:15} : {status}")
