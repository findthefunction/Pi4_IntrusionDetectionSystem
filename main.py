from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP
import threading

class PacketSniffer:
    """
    PacketSniffer captures network packets from specified interfaces using Scapy.
    It processes each packet and extracts relevant metadata for analysis.
    """

    def __init__(self, interfaces=["eth0"], callback=None, bpf_filter=""):
        """
        Initializes the PacketSniffer.

        Args:
            interfaces (list): List of network interfaces to monitor.
            callback (function): Function to call with packet information.
            bpf_filter (str): Berkeley Packet Filter string to filter captured packets.
        """
        self.interfaces = interfaces  # List of interfaces to monitor
        self.callback = callback      # Callback function to process packet info
        self.bpf_filter = bpf_filter  # BPF filter string

    def start(self):
        """
        Starts sniffing on all specified interfaces in separate threads.
        """
        for iface in self.interfaces:
            thread = threading.Thread(target=self._sniff, args=(iface,))
            thread.daemon = True  # Daemon threads exit when the main thread does
            thread.start()

    def _sniff(self, iface):
        """
        Sniffs packets on a single interface.

        Args:
            iface (str): Network interface to monitor.
        """
        print(f"Starting packet capture on interface: {iface}")
        sniff(iface=iface, prn=self._process_packet, store=False, filter=self.bpf_filter)

    def _process_packet(self, packet):
        """
        Processes a captured packet and extracts relevant information.

        Args:
            packet (scapy.Packet): The captured packet.
        """
        packet_info = {}

        # Extract Ethernet layer information if present
        if Ether in packet:
            ether_layer = packet[Ether]
            packet_info['src_mac'] = ether_layer.src
            packet_info['dst_mac'] = ether_layer.dst
            packet_info['eth_type'] = ether_layer.type

        # Extract IP layer information if present
        if IP in packet:
            ip_layer = packet[IP]
            packet_info['src_ip'] = ip_layer.src
            packet_info['dst_ip'] = ip_layer.dst
            packet_info['proto'] = ip_layer.proto

            # Extract Transport layer information
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

        # Additional metadata
        packet_info['length'] = len(packet)

        # Callback to pass the packet information for analysis
        if self.callback:
            self.callback(packet_info)
