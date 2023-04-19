
import sys
import argparse
from scapy.all import *
from scapy.layers.all import *


def run_test(interface_name):
    p = Ether() / fuzz(IP(src=str(RandIP()),dst=str(RandIP()),proto=6,version=4) / TCP() / Raw())
    p.show()
    sendp(p, iface=interface_name)
    print("*******\n")

    p = Ether() / fuzz(IP(src=str(RandIP()),dst=str(RandIP()),proto=17,version=4) / UDP() / Raw())
    p.show()
    sendp(p, iface=interface_name)
    print("*******\n")

    p = Ether() / fuzz(IPv6(src=str(RandIP6()),dst=str(RandIP6()),nh=6,version=6) / TCP() / Raw())
    p.show()
    sendp(p, iface=interface_name)
    print("*******\n")

    p = Ether() / fuzz(IPv6(src=str(RandIP6()),dst=str(RandIP6()),nh=17,version=6) / UDP() / Raw())
    p.show()
    sendp(p, iface=interface_name)
    print("*******\n")

    p = Ether() / fuzz(IP(src=str(RandIP()),dst=str(RandIP()),proto=17,version=4)\
        / UDP() / VXLAN() / IP(src=str(RandIP()),dst=str(RandIP()),proto=17,version=4) / UDP() / Raw())
    p.show()
    sendp(p, iface=interface_name)
    print("*******\n")


def parse():
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('-if', '--interface', help='Interface to send traffic from')

    return parser.parse_args()


if __name__ == "__main__":
    args = parse()
    interface = "eth2"

    if args.interface:
        interface = args.interface

    run_test(interface)