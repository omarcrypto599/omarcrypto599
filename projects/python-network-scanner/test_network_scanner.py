import ipaddress
import unittest
from unittest.mock import patch

from network_scanner import (
    ScanInputError,
    check_port,
    parse_ports,
    resolve_targets,
    validate_scope,
)


class PortParsingTests(unittest.TestCase):
    def test_parses_and_sorts_ports(self):
        self.assertEqual(parse_ports("443,80,8000-8002,80"), [80, 443, 8000, 8001, 8002])

    def test_rejects_invalid_port(self):
        with self.assertRaises(ScanInputError):
            parse_ports("80,70000")

    def test_rejects_descending_range(self):
        with self.assertRaises(ScanInputError):
            parse_ports("90-80")

    def test_rejects_too_many_ports(self):
        with self.assertRaises(ScanInputError):
            parse_ports("1-129")


class TargetSafetyTests(unittest.TestCase):
    def test_private_target_is_allowed(self):
        validate_scope([ipaddress.ip_address("192.168.1.10")])

    def test_public_target_requires_acknowledgement(self):
        address = ipaddress.ip_address("8.8.8.8")
        with self.assertRaises(ScanInputError):
            validate_scope([address])
        validate_scope([address], allow_public=True)

    def test_large_network_is_rejected(self):
        with self.assertRaises(ScanInputError):
            resolve_targets("10.0.0.0/16")

    def test_small_network_is_expanded(self):
        result = resolve_targets("192.168.1.0/30")
        self.assertEqual([str(item) for item in result], ["192.168.1.1", "192.168.1.2"])


class ConnectionTests(unittest.TestCase):
    @patch("network_scanner.socket.socket")
    def test_open_port_returns_true(self, mock_socket):
        connection = mock_socket.return_value.__enter__.return_value
        connection.connect_ex.return_value = 0
        self.assertTrue(check_port("127.0.0.1", 80, 0.2))

    @patch("network_scanner.socket.socket")
    def test_closed_port_returns_false(self, mock_socket):
        connection = mock_socket.return_value.__enter__.return_value
        connection.connect_ex.return_value = 111
        self.assertFalse(check_port("127.0.0.1", 80, 0.2))


if __name__ == "__main__":
    unittest.main()
