from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP

class PacketSniffer:
    def __init__(self, interface="eth0", callback=None, bpf_filter=""):
        self.interface = interface
        self.callback = callback
        self.bpf_filter = bpf_filter  # Berkeley Packet Filter string

    def start(self):
        sniff(iface=self.interface, prn=self._process_packet, store=False, filter=self.bpf_filter)

    def _process_packet(self, packet):
        packet_info = {}

        # Check for Ethernet Layer
        if Ether in packet:
            ether_layer = packet[Ether]
            packet_info['src_mac'] = ether_layer.src
            packet_info['dst_mac'] = ether_layer.dst
            packet_info['eth_type'] = ether_layer.type

        # Check for IP Layer
        if IP in packet:
            ip_layer = packet[IP]
            packet_info['src_ip'] = ip_layer.src
            packet_info['dst_ip'] = ip_layer.dst
            packet_info['proto'] = ip_layer.proto

            # Transport Layer Information
            if TCP in packet:
                tcp_layer = packet[TCP]
                packet_info['src_port'] = tcp_layer.sport
                packet_info['dst_port'] = tcp_layer.dport
                packet_info['flags'] = tcp_layer.flags
            elif UDP in packet:
                udp_layer = packet[UDP]
                packet_info['src_port'] = udp_layer.sport
                packet_info['dst_port'] = udp_layer.dport
            elif ICMP in packet:
                icmp_layer = packet[ICMP]
                packet_info['type'] = icmp_layer.type
                packet_info['code'] = icmp_layer.code

        # Additional Features
        packet_info['length'] = len(packet)

        if self.callback:
            self.callback(packet_info)
