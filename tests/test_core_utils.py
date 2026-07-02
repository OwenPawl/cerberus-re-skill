import json
import tempfile
import unittest
from pathlib import Path

from cerberus_re_skill.core.utils import write_json_atomic


class CoreUtilsTests(unittest.TestCase):
    def test_write_json_atomic_writes_valid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "artifact.json"

            write_json_atomic(path, {"kind": "fixture", "items": [1, 2, 3]})

            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["items"], [1, 2, 3])
            self.assertFalse(list(Path(tmp).glob(".*.tmp")))

    def test_write_json_atomic_preserves_existing_file_on_serialization_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "artifact.json"
            path.write_text('{"ok": true}\n', encoding="utf-8")

            with self.assertRaises(TypeError):
                write_json_atomic(path, {"bad": object()})

            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"ok": True})
            self.assertFalse(list(Path(tmp).glob(".*.tmp")))


if __name__ == "__main__":
    unittest.main()
