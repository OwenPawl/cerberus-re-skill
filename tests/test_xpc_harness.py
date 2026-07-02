import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cerberus_re_skill.modules.xpc_harness import generate_xpc_harness


class XpcHarnessTests(unittest.TestCase):
    def test_generated_harness_does_not_log_proxy_object_description(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exports = root / "exports"
            export_dir = exports / "proj" / "Program"
            export_dir.mkdir(parents=True)
            (export_dir / "xpc_surface.json").write_text(
                json.dumps(
                    {
                        "topology_hints": {
                            "probable_services": [{"value": "com.apple.automationd.xpc"}],
                            "probable_interfaces": [{"name": "ExampleAutomationDaemonXPCInterface"}],
                        }
                    }
                ),
                encoding="utf-8",
            )
            output = root / "harness.m"

            with patch("cerberus_re_skill.modules.xpc_harness.cfg.exports_dir", exports):
                result = generate_xpc_harness("proj", "Program", output=output)
            source = output.read_text(encoding="utf-8")

        self.assertTrue(result["ok"])
        self.assertIn("Remote proxy placeholder acquired without description", source)
        self.assertNotIn("Remote proxy placeholder: %@", source)


if __name__ == "__main__":
    unittest.main()
