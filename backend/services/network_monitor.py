from datetime import datetime
from collections import defaultdict
from backend.core.logger import logger
from backend.detection.event_service import event_service


class NetworkMonitor:
    """
    Defensive local network monitor.

    Collects normalized network-flow statistics and exposes them
    to the detection pipeline. It does not perform scanning,
    exploitation, or active network actions.
    """

    def __init__(self):
        self.running = False
        self.flows = defaultdict(lambda: {
            "packets": 0,
            "bytes": 0,
            "ports": set(),
            "last_seen": None,
        })

    def start(self):
        self.running = True
        logger.info("NETWORK_MONITOR | status=STARTED")
        return True

    def stop(self):
        self.running = False
        logger.info("NETWORK_MONITOR | status=STOPPED")
        return True

    def record_flow(
        self,
        source_ip,
        destination_ip,
        source_port=0,
        destination_port=0,
        protocol="UNKNOWN",
        packet_count=1,
        byte_count=0,
    ):
        if not self.running:
            return None

        key = (source_ip, destination_ip, protocol)

        flow = self.flows[key]
        flow["packets"] += packet_count
        flow["bytes"] += byte_count

        if destination_port:
            flow["ports"].add(destination_port)

        flow["last_seen"] = datetime.utcnow().isoformat()

        event = event_service.create_event(
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            packet_count=flow["packets"],
            unique_ports=len(flow["ports"]),
            risk_score=0,
            activity="NETWORK_FLOW",
        )

        logger.info(
            f"NETWORK_MONITOR | event_created={event['event_id']} | "
            f"src={source_ip} | dst={destination_ip}"
        )

        return event

    def get_flow(self, source_ip, destination_ip, protocol):
        key = (source_ip, destination_ip, protocol)
        flow = self.flows.get(key)

        if not flow:
            return None

        return {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": protocol,
            "packet_count": flow["packets"],
            "byte_count": flow["bytes"],
            "unique_ports": len(flow["ports"]),
            "last_seen": flow["last_seen"],
        }

    def get_stats(self):
        return {
            "running": self.running,
            "active_flows": len(self.flows),
            "total_packets": sum(
                flow["packets"] for flow in self.flows.values()
            ),
            "total_bytes": sum(
                flow["bytes"] for flow in self.flows.values()
            ),
        }


network_monitor = NetworkMonitor()


if __name__ == "__main__":
    print("=" * 60)
    print("CYBER SENTINEL X - NETWORK MONITOR")
    print("=" * 60)

    network_monitor.start()

    network_monitor.record_flow(
        source_ip="192.168.1.50",
        destination_ip="192.168.1.1",
        source_port=51520,
        destination_port=443,
        protocol="TCP",
        packet_count=5,
        byte_count=3200,
    )

    print("Monitor     :", "RUNNING" if network_monitor.running else "STOPPED")
    print("Statistics  :", network_monitor.get_stats())
    print("Network Monitor: READY")
