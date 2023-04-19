
import sys
import argparse
from scapy.all import *
from scapy.layers.all import *


def run_test(interface_name):
    packet1 = Ether() / IP(proto=6) / TCP() / Raw()
    sendp(packet1, iface=interface_name)
    packet2 = Ether() / IP(proto=17) / UDP() / Raw()
    sendp(packet2, iface=interface_name)
    packet3 = Ether() / IPv6(nh=6) / TCP() / Raw()
    sendp(packet3, iface=interface_name)
    packet4 = Ether() / IPv6(nh=17) / UDP() / Raw()
    sendp(packet4, iface=interface_name)
    packet5 = Ether() / IP(proto=17) / UDP() / VXLAN() / IP(proto=17) / UDP() / Raw()
    sendp(packet5, iface=interface_name)


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