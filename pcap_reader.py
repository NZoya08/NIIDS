from scapy.all import rdpcap


def read_pcap(file_path):
    """
    Read packets from a PCAP file.
    """
    packets = rdpcap(file_path)
    return packets