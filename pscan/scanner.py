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

        self.scanned = defaultdict(lambda: False)
        self.sport = randint(49152, 65535)
        
        try:
            self.myip = socket.gethostbyname(socket.gethostname())
            if targetip == "127.0.0.1":
                targetip = self.myip
        except:
            self.myip = "127.0.0.1"

        self.targetip = targetip
    
    def scan(self):
        print(f"Scanning {self.targetip}...")

        sniff = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sniff.bind((self.myip, 0))

        sniffer_thread = threading.Thread(target=self.packet_sniffer, args=(sniff,))
        sniffer_thread.setDaemon(True)
        sniffer_thread.start()

        for port in self.ports:
            thread = threading.Thread(target=self.packet_sender,args=(port,))
            thread.setDaemon(True)
            thread.start()

        sniffer_thread.join(5)

    def packet_sniffer(self, sniff):
        n_ports = len(self.ports)
        while n_ports != 0:
            data = sniff.recvfrom(65565)[0]

            ip = IP.load(data[:IP.size()])

            # check IP address
            if ip.src != self.targetip:
                continue

            if ip.dst != self.myip:
                continue

            data = data[IP.size():]
            tcp = TCP.load(data[:TCP.size()])

            # check port
            if tcp.dport != self.sport:
                continue
            
            # check SYN-ACK
            if tcp.flags != "SA":
                continue

            if self.scanned[tcp.sport]:
                continue

            try:
                service_name = socket.getservbyport(tcp.sport, "tcp")
            except OSError:
                service_name = "unknown"

            print(f"{tcp.sport}/{service_name} : open")

            self.scanned[tcp.sport] = True
            n_ports -= 1

        sniff.close()

    def packet_sender(self, port):
        # Send SYN packet
        head = TCP(sport=self.sport, dport=port, flags="S")
        head.update_chksum(saddr=self.myip, daddr=self.targetip)

        sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sender.sendto(head.bytes(), (self.targetip, port))

        sender.close()

if __name__ == "__main__":
    s = PortScanner(port=80)
    s.scan()