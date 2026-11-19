import os
import unittest
from docker_supply_lite.compose_linter import lint_compose


class TestComposeLinter(unittest.TestCase):
    def test_privileged_true_flagged(self):
        yml = "services:\n  app:\n    image: nginx:1.25\n    privileged: true\n    read_only: true\n    mem_limit: 128m\n"
        rules = [f.rule_id for f in lint_compose(yml)]
        self.assertIn("DC001", rules)

    def test_network_mode_host_flagged(self):
        yml = "services:\n  app:\n    image: nginx:1.25\n    network_mode: host\n    read_only: true\n    mem_limit: 128m\n"
        rules = [f.rule_id for f in lint_compose(yml)]
        self.assertIn("DC002", rules)

    def test_docker_sock_mount_flagged(self):
        yml = "services:\n  app:\n    image: nginx:1.25\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n    read_only: true\n    mem_limit: 128m\n"
        rules = [f.rule_id for f in lint_compose(yml)]
        self.assertIn("DC003", rules)

    def test_exposed_db_port_0000_flagged(self):
        yml = "services:\n  db:\n    image: postgres:16\n    ports:\n      - \"0.0.0.0:5432:5432\"\n    read_only: true\n    mem_limit: 256m\n"
        rules = [f.rule_id for f in lint_compose(yml)]
        self.assertIn("DC004", rules)

    def test_localhost_db_port_allowed(self):
        yml = "services:\n  db:\n    image: postgres:16\n    ports:\n      - \"127.0.0.1:5432:5432\"\n    read_only: true\n    mem_limit: 256m\n"
        rules = [f.rule_id for f in lint_compose(yml)]
        self.assertNotIn("DC004", rules)

    def test_missing_read_only_flagged(self):
        yml = "services:\n  app:\n    image: nginx:1.25\n    mem_limit: 128m\n"
        rules = [f.rule_id for f in lint_compose(yml)]
        self.assertIn("DC005", rules)

    def test_missing_mem_limit_flagged(self):
        yml = "services:\n  app:\n    image: nginx:1.25\n    read_only: true\n"
        rules = [f.rule_id for f in lint_compose(yml)]
        self.assertIn("DC006", rules)

    def test_unpinned_compose_image_flagged(self):
        yml = "services:\n  app:\n    image: nginx:latest\n    read_only: true\n    mem_limit: 128m\n"
        rules = [f.rule_id for f in lint_compose(yml)]
        self.assertIn("DC007", rules)

    def test_hardcoded_compose_secret_flagged(self):
        yml = "services:\n  app:\n    image: nginx:1.25\n    read_only: true\n    mem_limit: 128m\n    environment:\n      - JWT_SECRET=abc123\n"
        rules = [f.rule_id for f in lint_compose(yml)]
        self.assertIn("DC008", rules)

    def test_env_var_reference_allowed(self):
        yml = "services:\n  app:\n    image: nginx:1.25\n    read_only: true\n    mem_limit: 128m\n    environment:\n      - JWT_SECRET=${JWT_SECRET}\n"
        rules = [f.rule_id for f in lint_compose(yml)]
        self.assertNotIn("DC008", rules)

    def test_sample_compose_risky_and_hardened(self):
        base = os.path.dirname(os.path.dirname(__file__))
        with open(os.path.join(base, "samples", "docker-compose.risky.yml"), encoding="utf-8") as fh:
            risky_rules = {f.rule_id for f in lint_compose(fh.read())}
        self.assertTrue({"DC001", "DC002", "DC003", "DC004", "DC005", "DC006", "DC007", "DC008"}.issubset(risky_rules))

        with open(os.path.join(base, "samples", "docker-compose.hardened.yml"), encoding="utf-8") as fh:
            hardened_findings = lint_compose(fh.read())
        self.assertEqual(hardened_findings, [])


if __name__ == "__main__":
    unittest.main()
