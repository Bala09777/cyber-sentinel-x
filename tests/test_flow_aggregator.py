import unittest

from backend.pcap.flow_aggregator import FlowAggregator


class TestFlowAggregator(unittest.TestCase):

    def setUp(self):
        self.aggregator = FlowAggregator()
        self.packet = {
            "source_ip": "192.0.2.10",
            "destination_ip": "192.0.2.20",
            "source_port": 50000,
            "destination_port": 443,
            "protocol": "TCP",
            "packet_size": 120,
        }

    def test_packet_aggregation(self):
        self.aggregator.add_packet(self.packet)
        self.aggregator.add_packet(self.packet)

        flow = next(iter(self.aggregator.flows.values()))
        snapshot = self.aggregator.get_flow_snapshot(flow)

        self.assertEqual(snapshot["packets"], 2)
        self.assertEqual(snapshot["bytes"], 240)
        self.assertEqual(snapshot["protocol"], "TCP")

    def test_empty_packet(self):
        result = self.aggregator.add_packet(None)

        self.assertIsNone(result)
        self.assertEqual(len(self.aggregator.flows), 0)

    def test_flow_completion(self):
        self.aggregator.add_packet(self.packet)

        flow_key = next(iter(self.aggregator.flows))
        snapshot = self.aggregator.complete_flow(flow_key)

        self.assertEqual(snapshot["packets"], 1)
        self.assertEqual(snapshot["bytes"], 120)
        self.assertEqual(len(self.aggregator.flows), 0)
        self.assertEqual(self.aggregator.total_flows_completed, 1)

    def test_flow_callback(self):
        received = []
        self.aggregator.set_flow_callback(received.append)

        self.aggregator.add_packet(self.packet)
        flow_key = next(iter(self.aggregator.flows))

        self.aggregator.complete_flow(flow_key)

        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["protocol"], "TCP")
        self.assertEqual(received[0]["packets"], 1)


if __name__ == "__main__":
    unittest.main()
