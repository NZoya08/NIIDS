from scapy.all import sniff, get_if_list

import pandas as pd

try:
    from modules.feature_extraction import extract_features
except ImportError:  # pragma: no cover
    from feature_extraction import extract_features


# ============================================================
# LIST NETWORK INTERFACES
# ============================================================

def list_interfaces():
    """
    Return available Scapy network interfaces.
    """

    try:

        return get_if_list()

    except Exception as err:

        print(
            "Unable to list network interfaces:",
            err
        )

        return []


# ============================================================
# CAPTURE LIVE PACKETS
# ============================================================

def capture_live_packets(
    packet_count=20,
    iface=None
):
    """
    Capture live packets using Scapy/Npcap.

    Parameters
    ----------
    packet_count : int
        Number of packets to capture.

    iface : str, optional
        Network interface.

    Returns
    -------
    Scapy packet list
    """

    print("=" * 60)
    print("NIDS LIVE PACKET CAPTURE")
    print("=" * 60)

    print(
        f"Capturing {packet_count} packets..."
    )

    if iface:

        print(
            f"Interface: {iface}"
        )

    else:

        print(
            "Interface: Scapy default"
        )

    print()

    try:

        if iface:

            packets = sniff(
                count=packet_count,
                iface=iface
            )

        else:

            packets = sniff(
                count=packet_count
            )

        print(
            f"\nCaptured {len(packets)} packets."
        )

        return packets

    except PermissionError:

        print(
            "\nPermission error."
        )

        print(
            "Run the terminal as Administrator."
        )

        return []

    except Exception as err:

        print(
            "\nPacket capture error:",
            err
        )

        return []


# ============================================================
# CONVERT PACKETS TO FEATURES
# ============================================================

def packets_to_features(packets):
    """
    Convert captured packets into NIDS feature rows.
    """

    if packets is None:

        return pd.DataFrame()

    if len(packets) == 0:

        return pd.DataFrame()

    try:

        return extract_features(
            packets
        )

    except Exception as err:

        print(
            "Feature extraction error:",
            err
        )

        return pd.DataFrame()


# ============================================================
# CAPTURE TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("NIDS LIVE PACKET CAPTURE TEST")
    print("=" * 60)

    # --------------------------------------------------------
    # DISPLAY INTERFACES
    # --------------------------------------------------------

    interfaces = list_interfaces()

    print("\nAvailable Interfaces:")

    if interfaces:

        for index, interface in enumerate(
            interfaces,
            start=1
        ):

            print(
                f"{index}. {interface}"
            )

    else:

        print(
            "No interfaces found."
        )

    # --------------------------------------------------------
    # CAPTURE
    # --------------------------------------------------------

    packets = capture_live_packets(
        packet_count=20
    )

    print(
        f"\nPackets captured: {len(packets)}"
    )

    # --------------------------------------------------------
    # FEATURE EXTRACTION
    # --------------------------------------------------------

    features = packets_to_features(
        packets
    )

    print(
        f"Feature rows: {len(features)}"
    )

    # --------------------------------------------------------
    # DISPLAY FEATURES
    # --------------------------------------------------------

    if not features.empty:

        print(
            "\n========== EXTRACTED FEATURES =========="
        )

        display_columns = [

            "src_ip",

            "dst_ip",

            "src_port",

            "dst_port",

            "protocol_type",

            "service",

            "flag",

            "src_bytes",

            "dst_bytes",

            "packet_count",

            "count",

            "duration"
        ]

        available = [

            column

            for column in display_columns

            if column in features.columns
        ]

        print(
            features[
                available
            ].to_string(
                index=False
            )
        )

    else:

        print(
            "\nNo usable IP flows found."
        )