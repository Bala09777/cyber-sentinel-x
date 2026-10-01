import threading
import time
from collections import defaultdict
from datetime import datetime, timezone


class FlowAggregator:
    """
    CYBER SENTINEL X
    Real-Time Network Flow Aggregation Engine

    Purpose:
        Convert individual packets into short-lived network flows.

    Benefits:
        - Reduces detection pipeline load
        - Reduces database event volume
        - Provides better traffic behaviour features
        - Supports real-time SOC analytics
        - Creates scalable architecture
    """

    def __init__(
        self,
        window_seconds=5,
        idle_timeout=10,
        max_flows=10000,
    ):

        # =========================================================
        # CONFIGURATION
        # =========================================================

        self.window_seconds = float(
            window_seconds
        )

        self.idle_timeout = float(
            idle_timeout
        )

        self.max_flows = int(
            max_flows
        )

        # =========================================================
        # STATE
        # =========================================================

        self.running = False

        self.started_at = None
        self.stopped_at = None

        self.lock = threading.RLock()

        self.flows = {}

        self.completed_flows = []

        self.total_packets = 0
        self.total_bytes = 0

        self.total_flows_created = 0
        self.total_flows_completed = 0

        self.expired_flows = 0

        self.tcp_flows = 0
        self.udp_flows = 0
        self.icmp_flows = 0
        self.other_flows = 0

        # =========================================================
        # BACKGROUND THREAD
        # =========================================================

        self.stop_event = threading.Event()

        self.worker_thread = None

        # =========================================================
        # CALLBACK
        # =========================================================

        self.flow_callback = None

    # =============================================================
    # TIME
    # =============================================================

    @staticmethod
    def now():

        return datetime.now(
            timezone.utc
        ).isoformat()

    # =============================================================
    # FLOW KEY
    # =============================================================

    @staticmethod
    def build_flow_key(packet_data):

        source_ip = packet_data.get(
            "source_ip",
            ""
        )

        destination_ip = packet_data.get(
            "destination_ip",
            ""
        )

        source_port = packet_data.get(
            "source_port",
            0
        )

        destination_port = packet_data.get(
            "destination_port",
            0
        )

        protocol = packet_data.get(
            "protocol",
            "OTHER"
        )

        return (
            source_ip,
            destination_ip,
            int(source_port or 0),
            int(destination_port or 0),
            protocol,
        )

    # =============================================================
    # CREATE FLOW
    # =============================================================

    def create_flow(self, packet_data):

        flow_key = self.build_flow_key(
            packet_data
        )

        timestamp = time.time()

        flow = {

            "flow_id":
                self.generate_flow_id(),

            "source_ip":
                packet_data.get(
                    "source_ip"
                ),

            "destination_ip":
                packet_data.get(
                    "destination_ip"
                ),

            "source_port":
                int(
                    packet_data.get(
                        "source_port",
                        0
                    ) or 0
                ),

            "destination_port":
                int(
                    packet_data.get(
                        "destination_port",
                        0
                    ) or 0
                ),

            "protocol":
                packet_data.get(
                    "protocol",
                    "OTHER"
                ),

            "packets": 0,

            "bytes": 0,

            "first_seen":
                packet_data.get(
                    "timestamp"
                ) or self.now(),

            "last_seen":
                packet_data.get(
                    "timestamp"
                ) or self.now(),

            "first_seen_epoch":
                timestamp,

            "last_seen_epoch":
                timestamp,

            "unique_destination_ports":
                set(),

            "unique_destinations":
                set(),

            "tcp_flags":
                set(),

            "icmp_types":
                set(),

            "packet_sizes":
                [],

            "risk_score":
                0,

            "metadata":
                {},
        }

        self.flows[
            flow_key
        ] = flow

        self.total_flows_created += 1

        return flow

    # =============================================================
    # FLOW ID
    # =============================================================

    def generate_flow_id(self):

        timestamp = datetime.now(
            timezone.utc
        ).strftime(
            "%Y%m%d%H%M%S%f"
        )

        return (
            "FLOW-"
            + timestamp
        )

    # =============================================================
    # ADD PACKET
    # =============================================================

    def add_packet(self, packet_data):

        if not packet_data:

            return None

        with self.lock:

            # -----------------------------------------------------
            # Capacity protection
            # -----------------------------------------------------

            if (
                len(self.flows)
                >= self.max_flows
            ):

                self.expire_oldest_flow()

            flow_key = self.build_flow_key(
                packet_data
            )

            flow = self.flows.get(
                flow_key
            )

            if flow is None:

                flow = self.create_flow(
                    packet_data
                )

            # -----------------------------------------------------
            # Packet information
            # -----------------------------------------------------

            packet_size = int(
                packet_data.get(
                    "packet_size",
                    0
                ) or 0
            )

            timestamp = time.time()

            # -----------------------------------------------------
            # Counters
            # -----------------------------------------------------

            flow["packets"] += 1

            flow["bytes"] += packet_size

            flow["last_seen"] = (
                packet_data.get(
                    "timestamp"
                ) or self.now()
            )

            flow["last_seen_epoch"] = (
                timestamp
            )

            # -----------------------------------------------------
            # Ports
            # -----------------------------------------------------

            destination_port = int(
                packet_data.get(
                    "destination_port",
                    0
                ) or 0
            )

            if destination_port:

                flow[
                    "unique_destination_ports"
                ].add(
                    destination_port
                )

            # -----------------------------------------------------
            # Destinations
            # -----------------------------------------------------

            destination_ip = packet_data.get(
                "destination_ip"
            )

            if destination_ip:

                flow[
                    "unique_destinations"
                ].add(
                    destination_ip
                )

            # -----------------------------------------------------
            # Packet size
            # -----------------------------------------------------

            if packet_size:

                flow[
                    "packet_sizes"
                ].append(
                    packet_size
                )

            # -----------------------------------------------------
            # TCP flags
            # -----------------------------------------------------

            tcp_flags = packet_data.get(
                "tcp_flags"
            )

            if tcp_flags:

                flow[
                    "tcp_flags"
                ].add(
                    tcp_flags
                )

            # -----------------------------------------------------
            # ICMP
            # -----------------------------------------------------

            icmp_type = packet_data.get(
                "icmp_type"
            )

            if icmp_type is not None:

                flow[
                    "icmp_types"
                ].add(
                    icmp_type
                )

            # -----------------------------------------------------
            # Global counters
            # -----------------------------------------------------

            self.total_packets += 1

            self.total_bytes += packet_size

            return self.get_flow_snapshot(
                flow
            )

    # =============================================================
    # FLOW SNAPSHOT
    # =============================================================

    def get_flow_snapshot(self, flow):

        packet_sizes = flow.get(
            "packet_sizes",
            []
        )

        average_packet_size = 0

        if packet_sizes:

            average_packet_size = (
                sum(packet_sizes)
                /
                len(packet_sizes)
            )

        duration = (
            flow["last_seen_epoch"]
            -
            flow["first_seen_epoch"]
        )

        return {

            "flow_id":
                flow["flow_id"],

            "source_ip":
                flow["source_ip"],

            "destination_ip":
                flow["destination_ip"],

            "source_port":
                flow["source_port"],

            "destination_port":
                flow["destination_port"],

            "protocol":
                flow["protocol"],

            "packets":
                flow["packets"],

            "bytes":
                flow["bytes"],

            "duration_seconds":
                round(
                    max(
                        duration,
                        0
                    ),
                    4
                ),

            "packets_per_second":
                round(
                    flow["packets"]
                    /
                    max(
                        duration,
                        1
                    ),
                    4
                ),

            "bytes_per_second":
                round(
                    flow["bytes"]
                    /
                    max(
                        duration,
                        1
                    ),
                    4
                ),

            "unique_destination_ports":
                len(
                    flow[
                        "unique_destination_ports"
                    ]
                ),

            "unique_destinations":
                len(
                    flow[
                        "unique_destinations"
                    ]
                ),

            "average_packet_size":
                round(
                    average_packet_size,
                    2
                ),

            "first_seen":
                flow["first_seen"],

            "last_seen":
                flow["last_seen"],

            "tcp_flags":
                sorted(
                    flow["tcp_flags"]
                ),

            "icmp_types":
                sorted(
                    flow["icmp_types"]
                ),
        }

    # =============================================================
    # COMPLETE FLOW
    # =============================================================

    def complete_flow(
        self,
        flow_key,
        reason="WINDOW_EXPIRED",
    ):

        with self.lock:

            flow = self.flows.pop(
                flow_key,
                None
            )

            if flow is None:

                return None

            snapshot = (
                self.get_flow_snapshot(
                    flow
                )
            )

            snapshot[
                "completion_reason"
            ] = reason

            self.completed_flows.append(
                snapshot
            )

            self.total_flows_completed += 1

            protocol = (
                snapshot["protocol"]
            )

            if protocol == "TCP":

                self.tcp_flows += 1

            elif protocol == "UDP":

                self.udp_flows += 1

            elif protocol == "ICMP":

                self.icmp_flows += 1

            else:

                self.other_flows += 1

            # Keep memory bounded

            if (
                len(
                    self.completed_flows
                )
                > 1000
            ):

                self.completed_flows = (
                    self.completed_flows[-1000:]
                )

        # =========================================================
        # CALLBACK OUTSIDE LOCK
        # =========================================================

        if self.flow_callback:

            try:

                self.flow_callback(
                    snapshot
                )

            except Exception:

                pass

        return snapshot

    # =============================================================
    # EXPIRE FLOWS
    # =============================================================

    def expire_flows(self):

        current_time = time.time()

        expired = []

        with self.lock:

            for (
                flow_key,
                flow
            ) in list(
                self.flows.items()
            ):

                age = (
                    current_time
                    -
                    flow[
                        "first_seen_epoch"
                    ]
                )

                idle_age = (
                    current_time
                    -
                    flow[
                        "last_seen_epoch"
                    ]
                )

                # -------------------------------------------------
                # Window expiration
                # -------------------------------------------------

                if (
                    age
                    >=
                    self.window_seconds
                ):

                    expired.append(
                        (
                            flow_key,
                            "WINDOW_EXPIRED"
                        )
                    )

                    continue

                # -------------------------------------------------
                # Idle expiration
                # -------------------------------------------------

                if (
                    idle_age
                    >=
                    self.idle_timeout
                ):

                    expired.append(
                        (
                            flow_key,
                            "IDLE_TIMEOUT"
                        )
                    )

            for (
                flow_key,
                reason
            ) in expired:

                if reason == "IDLE_TIMEOUT":

                    self.expired_flows += 1

                self.complete_flow(
                    flow_key,
                    reason
                )

        return len(
            expired
        )

    # =============================================================
    # EXPIRE OLDEST FLOW
    # =============================================================

    def expire_oldest_flow(self):

        if not self.flows:

            return None

        oldest_key = min(

            self.flows,

            key=lambda key:
                self.flows[key][
                    "last_seen_epoch"
                ],
        )

        self.expired_flows += 1

        return self.complete_flow(
            oldest_key,
            "CAPACITY_LIMIT"
        )

    # =============================================================
    # BACKGROUND WORKER
    # =============================================================

    def worker_loop(self):

        while not self.stop_event.is_set():

            try:

                self.expire_flows()

            except Exception:

                pass

            self.stop_event.wait(
                1.0
            )

    # =============================================================
    # START
    # =============================================================

    def start(self):

        if self.running:

            return False

        self.running = True

        self.started_at = self.now()

        self.stopped_at = None

        self.stop_event.clear()

        self.worker_thread = (
            threading.Thread(
                target=self.worker_loop,
                name="CSX-FlowAggregator",
                daemon=True,
            )
        )

        self.worker_thread.start()

        return True

    # =============================================================
    # STOP
    # =============================================================

    def stop(self):

        if not self.running:

            return False

        self.running = False

        self.stop_event.set()

        # ---------------------------------------------------------
        # Complete remaining flows
        # ---------------------------------------------------------

        with self.lock:

            remaining_keys = list(
                self.flows.keys()
            )

        for flow_key in remaining_keys:

            self.complete_flow(
                flow_key,
                "ENGINE_STOPPED"
            )

        if self.worker_thread:

            self.worker_thread.join(
                timeout=2
            )

        self.worker_thread = None

        self.stopped_at = self.now()

        return True

    # =============================================================
    # SET CALLBACK
    # =============================================================

    def set_flow_callback(
        self,
        callback
    ):

        self.flow_callback = callback

    # =============================================================
    # ACTIVE FLOWS
    # =============================================================

    def get_active_flows(self):

        with self.lock:

            return [

                self.get_flow_snapshot(
                    flow
                )

                for flow
                in self.flows.values()
            ]

    # =============================================================
    # COMPLETED FLOWS
    # =============================================================

    def get_completed_flows(
        self,
        limit=100
    ):

        with self.lock:

            return list(
                self.completed_flows[
                    -limit:
                ]
            )

    # =============================================================
    # STATISTICS
    # =============================================================

    def get_statistics(self):

        with self.lock:

            protocol_distribution = {

                "TCP":
                    self.tcp_flows,

                "UDP":
                    self.udp_flows,

                "ICMP":
                    self.icmp_flows,

                "OTHER":
                    self.other_flows,
            }

            return {

                "status":
                    "RUNNING"
                    if self.running
                    else "STOPPED",

                "window_seconds":
                    self.window_seconds,

                "idle_timeout":
                    self.idle_timeout,

                "max_flows":
                    self.max_flows,

                "active_flows":
                    len(
                        self.flows
                    ),

                "completed_flows":
                    self.total_flows_completed,

                "total_flows_created":
                    self.total_flows_created,

                "total_packets":
                    self.total_packets,

                "total_bytes":
                    self.total_bytes,

                "expired_flows":
                    self.expired_flows,

                "protocol_distribution":
                    protocol_distribution,

                "started_at":
                    self.started_at,

                "stopped_at":
                    self.stopped_at,
            }

    # =============================================================
    # HEALTH CHECK
    # =============================================================

    def health_check(self):

        return {

            "service":
                "FLOW_AGGREGATOR",

            "status":
                "UP"
                if self.running
                else "DOWN",

            "active_flows":
                len(self.flows),

            "packets_processed":
                self.total_packets,

            "flows_created":
                self.total_flows_created,

            "flows_completed":
                self.total_flows_completed,

            "timestamp":
                self.now(),
        }


# =================================================================
# GLOBAL INSTANCE
# =================================================================

flow_aggregator = FlowAggregator(
    window_seconds=5,
    idle_timeout=10,
    max_flows=10000,
)


# =================================================================
# MODULE TEST
# =================================================================

if __name__ == "__main__":

    print("=" * 70)

    print(
        "CYBER SENTINEL X"
    )

    print(
        "FLOW AGGREGATION ENGINE"
    )

    print("=" * 70)

    print(
        "Window       : 5 seconds"
    )

    print(
        "Idle timeout : 10 seconds"
    )

    print(
        "Max flows    : 10000"
    )

    print("=" * 70)

    # -------------------------------------------------------------
    # Test callback
    # -------------------------------------------------------------

    def test_callback(flow):

        print()

        print(
            "[FLOW COMPLETED]"
        )

        print(
            f"ID       : "
            f"{flow['flow_id']}"
        )

        print(
            f"Source   : "
            f"{flow['source_ip']}"
        )

        print(
            f"Target   : "
            f"{flow['destination_ip']}"
        )

        print(
            f"Protocol : "
            f"{flow['protocol']}"
        )

        print(
            f"Packets  : "
            f"{flow['packets']}"
        )

        print(
            f"Bytes    : "
            f"{flow['bytes']}"
        )

    flow_aggregator.set_flow_callback(
        test_callback
    )

    flow_aggregator.start()

    # -------------------------------------------------------------
    # Test packets
    # -------------------------------------------------------------

    test_packets = [

        {
            "source_ip":
                "10.0.2.15",

            "destination_ip":
                "10.0.2.2",

            "source_port":
                0,

            "destination_port":
                0,

            "protocol":
                "ICMP",

            "packet_size":
                84,

            "timestamp":
                flow_aggregator.now(),
        },

        {
            "source_ip":
                "10.0.2.15",

            "destination_ip":
                "10.0.2.2",

            "source_port":
                0,

            "destination_port":
                0,

            "protocol":
                "ICMP",

            "packet_size":
                84,

            "timestamp":
                flow_aggregator.now(),
        },
    ]

    for packet in test_packets:

        flow_aggregator.add_packet(
            packet
        )

    print()

    print(
        "[ACTIVE FLOW STATISTICS]"
    )

    print(
        flow_aggregator.get_statistics()
    )

    # -------------------------------------------------------------
    # Wait for window completion
    # -------------------------------------------------------------

    print()

    print(
        "Waiting for flow window..."
    )

    time.sleep(6)

    print()

    print(
        "[FINAL STATISTICS]"
    )

    print(
        flow_aggregator.get_statistics()
    )

    flow_aggregator.stop()

    print()

    print(
        "FLOW AGGREGATION ENGINE READY"
    )
