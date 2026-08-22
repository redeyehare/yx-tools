import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cloudflare_speedtest import build_worker_upload_items, select_unique_best_ips


class UploadPayloadTests(unittest.TestCase):
    def test_select_unique_best_ips_deduplicates_same_ip_port_before_upload(self):
        rows = [
            {"ip": "1.1.1.1", "port": 443, "speed": 10, "region_code": "SIN", "region_name": "新加坡", "country": "新加坡"},
            {"ip": "1.1.1.1", "port": 443, "speed": 9, "region_code": "SIN", "region_name": "新加坡", "country": "新加坡"},
            {"ip": "2.2.2.2", "port": 443, "speed": 8, "region_code": "HKG", "region_name": "香港", "country": "中国香港"},
            {"ip": "3.3.3.3", "port": 8443, "speed": 7, "region_code": "NRT", "region_name": "东京成田", "country": "日本"},
        ]

        unique_rows = select_unique_best_ips(rows, 3)

        self.assertEqual(
            [(row["ip"], row["port"]) for row in unique_rows],
            [("1.1.1.1", 443), ("2.2.2.2", 443), ("3.3.3.3", 8443)],
        )

    def test_select_unique_best_ips_respects_unique_limit(self):
        rows = [
            {"ip": "1.1.1.1", "port": 443, "speed": 10, "region_code": "SIN", "region_name": "新加坡", "country": "新加坡"},
            {"ip": "2.2.2.2", "port": 443, "speed": 9, "region_code": "HKG", "region_name": "香港", "country": "中国香港"},
            {"ip": "3.3.3.3", "port": 443, "speed": 8, "region_code": "NRT", "region_name": "东京成田", "country": "日本"},
        ]

        unique_rows = select_unique_best_ips(rows, 2)

        self.assertEqual(
            [(row["ip"], row["port"]) for row in unique_rows],
            [("1.1.1.1", 443), ("2.2.2.2", 443)],
        )

    def test_region_code_builds_geo_prefixed_name(self):
        rows = [{
            "ip": "1.1.1.1",
            "port": 443,
            "region_code": "SIN",
            "region_name": "新加坡",
            "country": "新加坡",
        }]

        items = build_worker_upload_items(rows)

        self.assertEqual(items[0]["name"], "🇸🇬新加坡-优选节点-01")
        self.assertEqual(items[0]["regionCode"], "SIN")
        self.assertEqual(items[0]["country"], "新加坡")
        self.assertEqual(items[0]["sourceType"], "preferred")

    def test_missing_region_keeps_plain_base_name(self):
        rows = [{
            "ip": "1.1.1.1",
            "port": 443,
            "region_code": "",
            "region_name": "",
            "country": "",
        }]

        items = build_worker_upload_items(rows)

        self.assertEqual(items[0]["name"], "优选节点-01")

    def test_unknown_region_label_does_not_leak_into_name(self):
        rows = [{
            "ip": "1.1.1.1",
            "port": 443,
            "region_code": "",
            "region_name": "未知地区",
            "country": "",
        }]

        items = build_worker_upload_items(rows)

        self.assertEqual(items[0]["name"], "优选节点-01")


if __name__ == "__main__":
    unittest.main()
