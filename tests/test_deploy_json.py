import json
import tempfile
import unittest
from pathlib import Path

from cloudflare_speedtest import load_deploy_json, load_deploy_target


class DeployJsonTests(unittest.TestCase):
    def test_load_deploy_json_returns_worker_domain_and_uuid(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "deploy_result.json"
            p.write_text(json.dumps({
                "workerDomain": "example.workers.dev",
                "uuid": "abc",
            }), encoding="utf-8")

            worker_domain, uuid = load_deploy_json(str(p))
            self.assertEqual(worker_domain, "example.workers.dev")
            self.assertEqual(uuid, "abc")

    def test_load_deploy_json_accepts_snake_case_worker_domain(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "deploy_result.json"
            p.write_text(json.dumps({
                "worker_domain": "example.workers.dev",
                "uuid": "abc",
            }), encoding="utf-8")

            worker_domain, uuid = load_deploy_json(str(p))
            self.assertEqual(worker_domain, "example.workers.dev")
            self.assertEqual(uuid, "abc")

    def test_load_deploy_json_rejects_missing_fields(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "deploy_result.json"
            p.write_text(json.dumps({
                "workerDomain": "",
                "uuid": "",
            }), encoding="utf-8")

            with self.assertRaises(ValueError):
                load_deploy_json(str(p))

    def test_load_deploy_target_prefers_probe_and_api_domains(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "deploy_result.json"
            p.write_text(json.dumps({
                "apiDomain": "example.workers.dev",
                "probeDomain": "example.account.workers.dev",
                "uuid": "abc",
            }), encoding="utf-8")

            target = load_deploy_target(str(p))
            self.assertEqual(target["api_domain"], "example.workers.dev")
            self.assertEqual(target["probe_domain"], "example.account.workers.dev")
            self.assertEqual(target["uuid"], "abc")

    def test_load_deploy_json_rejects_pages_domain(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "deploy_result.json"
            p.write_text(json.dumps({
                "deployType": "pages",
                "workerDomain": "example.pages.dev",
                "uuid": "abc",
            }), encoding="utf-8")

            with self.assertRaises(ValueError):
                load_deploy_json(str(p))


if __name__ == "__main__":
    unittest.main()
