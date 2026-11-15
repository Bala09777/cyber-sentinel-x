import os
import threading
from collections import Counter
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP

from backend.core.logger import logger
from backend.database.manager import db
from backend.detection.pipeline import pipeline
from backend.pcap.flow_aggregator import flow_aggregator


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
        self._telemetry_stop = threading.Event()
        self._telemetry_thread = None

        # Flow-based monitoring
        self.flow_aggregator = flow_aggregator
        self.flow_aggregator.set_flow_callback(
            self.completed_flow_callback
        )

    def save_network_metrics(self):
        try:
            stats = self.flow_aggregator.get_statistics()
            protocols = stats.get("protocol_distribution", {})

            db.insert(
                "network_metrics",
                {
                    "timestamp": datetime.now().isoformat(),
                    "status": stats.get("status", "STOPPED"),
                    "active_flows": stats.get("active_flows", 0),
                    "completed_flows": stats.get("completed_flows", 0),
                    "total_flows_created": stats.get("total_flows_created", 0),
                    "total_packets": stats.get("total_packets", 0),
                    "total_bytes": stats.get("total_bytes", 0),
                    "expired_flows": stats.get("expired_flows", 0),
                    "tcp_flows": protocols.get("TCP", 0),
                    "udp_flows": protocols.get("UDP", 0),
                    "icmp_flows": protocols.get("ICMP", 0),
                    "other_flows": protocols.get("OTHER", 0),
                }
            )

        except Exception as exc:
            logger.exception(
                f"NETWORK_METRICS_SAVE_ERROR | {exc}"
            )

    def _telemetry_heartbeat(self):
        # Capture may be alive even if no flows have completed recently.
        # Persist a heartbeat so the browser never confuses idle capture with STOPPED.
        while not self._telemetry_stop.wait(5):
            if self.running:
                self.save_network_metrics()

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

            # Send packet into the flow engine.
            # Detection pipeline runs when the flow completes.
            self.flow_aggregator.add_packet(data)

            print(
                f"[LIVE] "
                f"{protocol:<5} "
                f"{source_ip}:{data['source_port']} -> "
                f"{destination_ip}:{destination_port} | "
                f"FLOW_BUFFERED"
            )

        except Exception as exc:
            logger.exception(
                f"LIVE_CAPTURE_PACKET_ERROR | {exc}"
            )

    def completed_flow_callback(self, flow):
        """
        Process a completed network flow through the
        Cyber Sentinel X detection pipeline.
        """

        try:
            unique_ports = int(
                flow.get("unique_destination_ports", 0) or 0
            )

            packet_count = int(
                flow.get("packets", 0) or 0
            )

            event = {
                "source_ip": flow.get("source_ip"),
                "destination_ip": flow.get("destination_ip"),
                "source_port": flow.get("source_port", 0),
                "destination_port": flow.get("destination_port", 0),
                "protocol": flow.get("protocol", "OTHER"),
                "packet_count": packet_count,
                "unique_ports": unique_ports,
                "activity": "NETWORK_FLOW",
            }

            shadow_result = {"method": "NOT_AVAILABLE"}
            # Experimental UNSW-NB15 ML shadow mode.
            # Predictions are observational only.
            # They do not affect risk, alerts, incidents or database.
            try:
                from backend.ml.unsw_inference import unsw_inference

                if unsw_inference.model is None:
                    unsw_inference.load()

                shadow_result = unsw_inference.predict({
                    "packet_count": packet_count,
                    "bytes": flow.get("bytes"),
                    "duration_seconds": flow.get("duration_seconds"),
                    "protocol": flow.get("protocol"),
                })

                print(
                    f"[ML SHADOW] "
                    f"flow={flow.get('flow_id', 'UNKNOWN')} | "
                    f"score={shadow_result.get('anomaly_score', 'N/A')} | "
                    f"anomaly={shadow_result.get('is_anomaly', False)} | "
                    f"method={shadow_result.get('method')}"
                )

            except Exception as shadow_exc:
                logger.warning(
                    f"ML_SHADOW_ERROR | {shadow_exc}"
                )

            result = pipeline.process_event(event)

            # Keep experimental shadow scores auditable without affecting alerts,
            # incidents or the production ML baseline.
            if shadow_result.get("method") in ("UNSW_EXPERIMENTAL", "UNSW_V34_SHADOW"):
                try:
                    from datetime import timezone
                    db.insert("shadow_ml_predictions", {
                        "event_id": result["event"]["event_id"],
                        "flow_id": str(flow.get("flow_id", "")),
                        "anomaly_score": float(shadow_result["anomaly_score"]),
                        "method": shadow_result["method"],
                        "is_anomaly": 1 if shadow_result["is_anomaly"] else 0,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                except Exception as exc:
                    logger.warning(f"SHADOW_AUDIT_ERROR | {type(exc).__name__}")

            self.save_network_metrics()

            risk_data = result.get("risk", {}) or {}

            risk_score = result.get(
                "risk_score",
                risk_data.get("risk_score", 0)
            )

            severity = result.get(
                "severity",
                risk_data.get("severity", "UNKNOWN")
            )

            print(
                f"[FLOW] "
                f"{flow.get('flow_id', 'UNKNOWN')} | "
                f"{flow.get('source_ip')} -> "
                f"{flow.get('destination_ip')} | "
                f"protocol={flow.get('protocol')} | "
                f"packets={packet_count} | "
                f"risk={risk_score} | "
                f"severity={severity}"
            )

        except Exception as exc:
            logger.exception(
                f"FLOW_PIPELINE_ERROR | {exc}"
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
            self.flow_aggregator.start()
            self._telemetry_stop.clear()
            self.save_network_metrics()
            self._telemetry_thread = threading.Thread(
                target=self._telemetry_heartbeat, daemon=True,
                name="csx-network-telemetry")
            self._telemetry_thread.start()

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
            self._telemetry_stop.set()
            if self._telemetry_thread is not None:
                self._telemetry_thread.join(timeout=6)

            try:
                self.flow_aggregator.stop()
            except Exception as exc:
                logger.exception(
                    f"FLOW_ENGINE_STOP_ERROR | {exc}"
                )

            self.save_network_metrics()
            logger.info(
                f"LIVE_CAPTURE_STOPPED | "
                f"packets={self.packet_count}"
            )

            print("\nLIVE CAPTURE STOPPED")
            print(f"Packets observed: {self.packet_count}")


live_capture = LiveCaptureService()


if __name__ == "__main__":
    from backend.database.schema import initialize_database
    initialize_database()
    live_capture.start()
