import pandas as pd
import numpy as np
from scapy.all import rdpcap, IP, TCP, UDP, sniff, wrpcap
from collections import defaultdict

def sniff_packets(interface: str, packet_count: int):
    packets = sniff(iface=interface, count=packet_count)
    wrpcap("packets.pcap", packets)

def parse_pcap(file_path):
    packets = rdpcap(file_path)
    flows = defaultdict(list)

    for pkt in packets:
        if IP in pkt and (TCP in pkt or UDP in pkt):
            proto = pkt[IP].proto
            sport = pkt.sport
            dport = pkt.dport
            flow_key = (pkt[IP].src, sport, pkt[IP].dst, dport, proto)
            flows[flow_key].append(pkt)

    return flows

def extract_features(flow, key):
    src_ip = key[0]
    timestamps = [float(pkt.time) for pkt in flow]
    sizes = [len(pkt) for pkt in flow]
    duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0

    fwd_sizes, bwd_sizes = [], []
    fwd_times, bwd_times = [], []
    flags = {'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0, 'URG': 0, 'CWE': 0, 'ECE': 0}
    fwd_flags = {'PSH': 0, 'URG': 0}
    bwd_flags = {'PSH': 0, 'URG': 0}
    fwd_header_len = bwd_header_len = 0

    for pkt in flow:
        if IP in pkt:
            direction = 'fwd' if pkt[IP].src == src_ip else 'bwd'
            length = len(pkt)

            if direction == 'fwd':
                fwd_sizes.append(length)
                fwd_times.append(float(pkt.time))
                fwd_header_len += pkt[IP].ihl * 4
            else:
                bwd_sizes.append(length)
                bwd_times.append(float(pkt.time))
                bwd_header_len += pkt[IP].ihl * 4

            if TCP in pkt:
                tcp_flags = pkt[TCP].flags
                flags['FIN'] += int(tcp_flags & 0x01 != 0)
                flags['SYN'] += int(tcp_flags & 0x02 != 0)
                flags['RST'] += int(tcp_flags & 0x04 != 0)
                flags['PSH'] += int(tcp_flags & 0x08 != 0)
                flags['ACK'] += int(tcp_flags & 0x10 != 0)
                flags['URG'] += int(tcp_flags & 0x20 != 0)
                flags['ECE'] += int(tcp_flags & 0x40 != 0)
                flags['CWE'] += int(tcp_flags & 0x80 != 0)
                if direction == 'fwd':
                    fwd_flags['PSH'] += int(tcp_flags & 0x08 != 0)
                    fwd_flags['URG'] += int(tcp_flags & 0x20 != 0)
                else:
                    bwd_flags['PSH'] += int(tcp_flags & 0x08 != 0)
                    bwd_flags['URG'] += int(tcp_flags & 0x20 != 0)

    # Inter-arrival times
    iat = np.diff(sorted(timestamps)) if len(timestamps) > 1 else [0]
    fwd_iat = np.diff(sorted(fwd_times)) if len(fwd_times) > 1 else [0]
    bwd_iat = np.diff(sorted(bwd_times)) if len(bwd_times) > 1 else [0]

    return {
        "Source IP": key[0],
        "Source Port": key[1],
        "Destination IP": key[2],
        "Destination Port": key[3],
        "Protocol": key[4],
        "Flow Duration": duration,
        "Total Fwd Packets": len(fwd_sizes),
        "Total Backward Packets": len(bwd_sizes),
        "Total Length of Fwd Packets": sum(fwd_sizes),
        "Total Length of Bwd Packets": sum(bwd_sizes),
        "Fwd Packet Length Max": max(fwd_sizes, default=0),
        "Fwd Packet Length Min": min(fwd_sizes, default=0),
        "Fwd Packet Length Mean": np.mean(fwd_sizes) if fwd_sizes else 0,
        "Fwd Packet Length Std": np.std(fwd_sizes) if fwd_sizes else 0,
        "Bwd Packet Length Max": max(bwd_sizes, default=0),
        "Bwd Packet Length Min": min(bwd_sizes, default=0),
        "Bwd Packet Length Mean": np.mean(bwd_sizes) if bwd_sizes else 0,
        "Bwd Packet Length Std": np.std(bwd_sizes) if bwd_sizes else 0,
        "Flow Bytes/s": sum(sizes)/duration if duration > 0 else 0,
        "Flow Packets/s": len(flow)/duration if duration > 0 else 0,
        "Flow IAT Mean": np.mean(iat),
        "Flow IAT Std": np.std(iat),
        "Flow IAT Max": np.max(iat),
        "Flow IAT Min": np.min(iat),
        "Fwd IAT Total": sum(fwd_iat),
        "Fwd IAT Mean": np.mean(fwd_iat),
        "Fwd IAT Std": np.std(fwd_iat),
        "Fwd IAT Max": np.max(fwd_iat),
        "Fwd IAT Min": np.min(fwd_iat),
        "Bwd IAT Total": sum(bwd_iat),
        "Bwd IAT Mean": np.mean(bwd_iat),
        "Bwd IAT Std": np.std(bwd_iat),
        "Bwd IAT Max": np.max(bwd_iat),
        "Bwd IAT Min": np.min(bwd_iat),
        "Fwd PSH Flags": fwd_flags['PSH'],
        "Bwd PSH Flags": bwd_flags['PSH'],
        "Fwd URG Flags": fwd_flags['URG'],
        "Bwd URG Flags": bwd_flags['URG'],
        "Fwd Header Length": fwd_header_len,
        "Bwd Header Length": bwd_header_len,
        "Fwd Packets/s": len(fwd_sizes)/duration if duration > 0 else 0,
        "Bwd Packets/s": len(bwd_sizes)/duration if duration > 0 else 0,
        "Min Packet Length": min(sizes, default=0),
        "Max Packet Length": max(sizes, default=0),
        "Packet Length Mean": np.mean(sizes),
        "Packet Length Std": np.std(sizes),
        "Packet Length Variance": np.var(sizes),
        **flags
    }

def main(pcap_path, output_csv):
    sniff_packets("enp4s0", 50)
    flows = parse_pcap(pcap_path)
    data = [extract_features(pkts, key) for key, pkts in flows.items()]
    df = pd.DataFrame(data)
    df.to_csv(output_csv, index=False)
    print(f"Saved flow features to {output_csv}")

if __name__ == "__main__":
    main("packets.pcap", "features.csv")