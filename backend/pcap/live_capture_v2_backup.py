import os
from collections import Counter
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP

from backend.core.logger import logger
from backend.detection.pipeline import pipeline


class LiveCaptureService:
    """
    CYBER SENTINEL X
    Passive real-time packet monitoring service.
    """

    def __init__(self, interface=None):
        self.interface = interface or os.getenv("CSX_INTERFACE", "eth0")

        self.running = False
        self.packet_count = 0

        self.protocol_counts = Counter()
        self.source_counts = Counter()
        self.destination_counts = Counter()
        self.port_counts = Counter()

        self.started_at = None

    def reset(self):
        self.packet_count = 0
        self.protocol_counts.clear()
        self.source_counts.clear()
        self.destination_counts.clear()
        self.port_counts.clear()

    def parse_packet(self, packet):
        if not packet.haslayer(IP):
            return None

        ip = packet[IP]

        protocol = "OTHER"
        source_port = 0
        destination_port = 0

        if packet.haslayer(TCP):
            protocol = "TCP"
            source_port = int(packet[TCP].sport)
            destination_port = int(packet[TCP].dport)

        elif packet.haslayer(UDP):
            protocol = "UDP"
            source_port = int(packet[UDP].sport)
            destination_port = int(packet[UDP].dport)

        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        return {
            "source_ip": ip.src,
            "destination_ip": ip.dst,
            "source_port": source_port,
            "destination_port": destination_port,
            "protocol": protocol,
            "packet_size": len(packet),
            "timestamp": datetime.now().isoformat(),
        }

    def packet_callback(self, packet):
        try:
            data = self.parse_packet(packet)

            if not data:
                return

            self.packet_count += 1

            protocol = data["protocol"]
            source_ip = data["source_ip"]
            destination_ip = data["destination_ip"]
            destination_port = data["destination_port"]

            self.protocol_counts[protocol] += 1
            self.source_counts[source_ip] += 1
            self.destination_counts[destination_ip] += 1

            if destination_port:
                self.port_counts[destination_port] += 1

            event = {
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "source_port": data["source_port"],
                "destination_port": destination_port,
                "protocol": protocol,
                "packet_count": 1,
                "unique_ports": 1,
                "activity": "LIVE_NETWORK_TRAFFIC",
            }

            result = pipeline.process_event(event)

            print(
                f"[LIVE] "
                f"{protocol:<5} "
                f"{source_ip}:{data['source_port']} -> "
                f"{destination_ip}:{destination_port} | "
                f"risk={result.get('risk_score', 0)} | "
                f"severity={result.get('severity', 'UNKNOWN')}"
            )

        except Exception as exc:
            logger.exception(
                f"LIVE_CAPTURE_PACKET_ERROR | {exc}"
            )

    def statistics(self):
        return {
            "interface": self.interface,
            "running": self.running,
            "packet_count": self.packet_count,
            "protocols": dict(self.protocol_counts),
            "top_sources": self.source_counts.most_common(10),
            "top_destinations": self.destination_counts.most_common(10),
            "top_ports": self.port_counts.most_common(10),
            "started_at": self.started_at,
        }

    def start(self):
        if self.running:
            print("Live capture already running.")
            return

        self.reset()
        self.running = True
        self.started_at = datetime.now().isoformat()

        print("=" * 70)
        print("CYBER SENTINEL X")
        print("REAL-TIME NETWORK MONITORING ENGINE")
        print("=" * 70)
        print(f"Interface : {self.interface}")
        print("Mode      : PASSIVE MONITORING")
        print("Engine    : SCAPY")
        print("Pipeline  : ENABLED")
        print("Status    : RUNNING")
        print("=" * 70)

        logger.info(
            f"LIVE_CAPTURE_STARTED | interface={self.interface}"
        )

        try:
            sniff(
                iface=self.interface,
                filter="ip",
                prn=self.packet_callback,
                store=False
            )

        except KeyboardInterrupt:
            print("\nStopping live capture...")

        except Exception as exc:
            logger.exception(
                f"LIVE_CAPTURE_ERROR | {exc}"
            )

        finally:
            self.running = False

            logger.info(
                f"LIVE_CAPTURE_STOPPED | "
                f"packets={self.packet_count}"
            )

            print("\nLIVE CAPTURE STOPPED")
            print(f"Packets observed: {self.packet_count}")


live_capture = LiveCaptureService()


if __name__ == "__main__":
    live_capture.start()
