import os
import unittest
from docker_supply_lite.dockerfile_linter import lint_dockerfile


class TestDockerfileLinter(unittest.TestCase):
    def test_unpinned_latest_tag(self):
        df = "FROM python:latest\nUSER app\nHEALTHCHECK CMD true\n"
        rules = [f.rule_id for f in lint_dockerfile(df)]
        self.assertIn("DF001", rules)

    def test_untagged_image(self):
        df = "FROM alpine\nUSER app\nHEALTHCHECK CMD true\n"
        rules = [f.rule_id for f in lint_dockerfile(df)]
        self.assertIn("DF001", rules)

    def test_pinned_sha256_passes(self):
        df = "FROM python:3.12-slim@sha256:abc123\nUSER app\nHEALTHCHECK CMD true\n"
        self.assertEqual(lint_dockerfile(df), [])

    def test_scratch_image_passes(self):
        df = "FROM scratch\nUSER 1000\nHEALTHCHECK CMD true\n"
        self.assertEqual(lint_dockerfile(df), [])

    def test_missing_user_flagged(self):
        df = "FROM python:3.12-slim\nHEALTHCHECK CMD true\n"
        rules = [f.rule_id for f in lint_dockerfile(df)]
        self.assertIn("DF002", rules)

    def test_explicit_root_user_flagged(self):
        df = "FROM python:3.12-slim\nUSER root\nHEALTHCHECK CMD true\n"
        rules = [f.rule_id for f in lint_dockerfile(df)]
        self.assertIn("DF002", rules)

    def test_curl_pipe_sh_flagged(self):
        df = "FROM python:3.12-slim\nRUN curl -fsSL https://x.io/a.sh | sh\nUSER app\nHEALTHCHECK CMD true\n"
        rules = [f.rule_id for f in lint_dockerfile(df)]
        self.assertIn("DF003", rules)

    def test_wget_pipe_bash_flagged(self):
        df = "FROM python:3.12-slim\nRUN wget -qO- https://x.io/a.sh | bash\nUSER app\nHEALTHCHECK CMD true\n"
        rules = [f.rule_id for f in lint_dockerfile(df)]
        self.assertIn("DF003", rules)

    def test_add_remote_url_flagged(self):
        df = "FROM python:3.12-slim\nADD https://x.io/app.tgz /tmp/\nUSER app\nHEALTHCHECK CMD true\n"
        rules = [f.rule_id for f in lint_dockerfile(df)]
        self.assertIn("DF004", rules)

    def test_add_local_file_allowed(self):
        df = "FROM python:3.12-slim\nADD app.tgz /tmp/\nUSER app\nHEALTHCHECK CMD true\n"
        rules = [f.rule_id for f in lint_dockerfile(df)]
        self.assertNotIn("DF004", rules)

    def test_hardcoded_env_secret_flagged(self):
        df = "FROM python:3.12-slim\nENV DB_PASSWORD=mysecret\nUSER app\nHEALTHCHECK CMD true\n"
        rules = [f.rule_id for f in lint_dockerfile(df)]
        self.assertIn("DF005", rules)

    def test_hardcoded_arg_token_flagged(self):
        df = "FROM python:3.12-slim\nARG API_TOKEN=tok_123\nUSER app\nHEALTHCHECK CMD true\n"
        rules = [f.rule_id for f in lint_dockerfile(df)]
        self.assertIn("DF005", rules)

    def test_missing_healthcheck_flagged(self):
        df = "FROM python:3.12-slim\nUSER app\n"
        rules = [f.rule_id for f in lint_dockerfile(df)]
        self.assertIn("DF006", rules)

    def test_sample_risky_and_hardened(self):
        base = os.path.dirname(os.path.dirname(__file__))
        with open(os.path.join(base, "samples", "Dockerfile.risky"), encoding="utf-8") as fh:
            risky_rules = {f.rule_id for f in lint_dockerfile(fh.read())}
        self.assertTrue({"DF001", "DF002", "DF003", "DF004", "DF005", "DF006"}.issubset(risky_rules))

        with open(os.path.join(base, "samples", "Dockerfile.hardened"), encoding="utf-8") as fh:
            hardened_findings = lint_dockerfile(fh.read())
        self.assertEqual(hardened_findings, [])


if __name__ == "__main__":
    unittest.main()
