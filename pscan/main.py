import argparse
import sys
from pscan.scanner import PortScanner

def getargs():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t",
        help="Target ip address you want to scan",
        default="127.0.0.1")
    parser.add_argument("-p",
        help="Port number or port number range (e.g. 80, 0-1023)",
        default="0-1023")
    return parser.parse_args()

def main():
    args = getargs()

    if "-" in args.p:
        start, end = map(int, args.p.split("-"))
        scanner = PortScanner(targetip=args.t, port=range(start, end + 1))
    else:
        port = int(args.p)
        scanner = PortScanner(targetip=args.t, port=port)

    scanner.scan()