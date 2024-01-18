# Packet Sniffer Program
# Author: Safi Ullah Khan
# Description: This program uses Scapy to sniff network packets and extract information from IP, TCP, UDP, and ICMP layers.
#              It resolves IP addresses to hostnames and prints detailed information about each packet including protocol,
#              source and destination IP addresses, ports, TTL, length, and optional data for TCP/UDP packets.
#              It also includes frame length, ACK, and checksum for TCP packets, and checksum for UDP and ICMP packets.
#              The program starts by printing a header with the author's name and then begins packet sniffing.
import socket
from scapy.all import *

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_name = resolve_hostname(src_ip)
        dst_name = resolve_hostname(dst_ip)
        ttl = packet[IP].ttl
        length = len(packet)
        proto = packet[IP].proto

        if proto == 6:  # TCP
            proto_name = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"IP Packet: {src_name} ({src_ip}) -> {dst_name} ({dst_ip}),\nTTL: {ttl},\nLength: {length},\nProtocol: {proto_name},\nSrc Port: {src_port},\nDst Port: {dst_port}")

            data = packet[TCP].payload
            if data:
                print(f"Data: {data}")

            frame_length = len(packet)
            ack = packet[TCP].ack
            checksum = packet[TCP].chksum
            print(f"Frame Length: {frame_length},\nACK: {ack},\nChecksum: {checksum}")

        elif proto == 17:  # UDP
            proto_name = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"IP Packet: {src_name} ({src_ip}) -> {dst_name} ({dst_ip}),\nTTL: {ttl},\nLength: {length},\nProtocol: {proto_name},\nSrc Port: {src_port},\nDst Port: {dst_port}")

            data = packet[UDP].payload
            if data:
                print(f"Data: {data}")

            frame_length = len(packet)
            checksum = packet[UDP].chksum
            print(f"Frame Length: {frame_length},\nChecksum: {checksum}")

        elif proto == 1:  # ICMP
            proto_name = "ICMP"
            print(f"IP Packet: {src_name} ({src_ip}) -> {dst_name} ({dst_ip}),\nTTL: {ttl},\nLength: {length},\nProtocol: {proto_name}")

            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            print(f"ICMP Type: {icmp_type},\nCode: {icmp_code}")

            frame_length = len(packet)
            checksum = packet[ICMP].chksum
            print(f"Frame Length: {frame_length},\nChecksum: {checksum}")

        else:
            print(f"IP Packet: {src_name} ({src_ip}) -> {dst_name} ({dst_ip}),\nTTL: {ttl},\nLength: {length},\nUnknown Protocol")


print("Packet Sniffer")
print("--------------------")
print("Safi Ullah Khan")
print("--------------------")
sniff(prn=packet_callback, store=0)
