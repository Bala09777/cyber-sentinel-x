from collections import Counter
from pathlib import Path

from scapy.all import rdpcap, IP, TCP, UDP, ICMP


class PCAPAnalyzer:
    """Defensive PCAP metadata analyzer."""

    def analyze(self, file_path):
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError("PCAP file not found")

        if path.suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
            raise ValueError("Unsupported capture format")

        packets = rdpcap(str(path))

        protocols = Counter()
        source_ips = Counter()
        destination_ips = Counter()
        source_ports = Counter()
        destination_ports = Counter()

        total_bytes = 0

        for packet in packets:
            total_bytes += len(packet)

            if IP not in packet:
                protocols["OTHER"] += 1
                continue

            source_ips[packet[IP].src] += 1
            destination_ips[packet[IP].dst] += 1

            if TCP in packet:
                protocols["TCP"] += 1
                source_ports[packet[TCP].sport] += 1
                destination_ports[packet[TCP].dport] += 1

            elif UDP in packet:
                protocols["UDP"] += 1
                source_ports[packet[UDP].sport] += 1
                destination_ports[packet[UDP].dport] += 1

            elif ICMP in packet:
                protocols["ICMP"] += 1

            else:
                protocols["OTHER"] += 1

        return {
            "file": path.name,
            "packet_count": len(packets),
            "total_bytes": total_bytes,
            "protocol_distribution": dict(protocols),
            "top_source_ips": source_ips.most_common(10),
            "top_destination_ips": destination_ips.most_common(10),
            "top_source_ports": source_ports.most_common(10),
            "top_destination_ports": destination_ports.most_common(10),
        }


pcap_analyzer = PCAPAnalyzer()


if __name__ == "__main__":
    print("CYBER SENTINEL X - PCAP ANALYZER")
    print("Status: READY")
