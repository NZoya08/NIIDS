from scapy.all import sniff


def capture_live_packets(packet_count=10):
    """
    Capture live network packets.
    """
    packets = sniff(count=packet_count)
    return packets