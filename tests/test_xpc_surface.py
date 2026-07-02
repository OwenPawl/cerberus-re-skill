import json
import tempfile
import unittest
from pathlib import Path

from cerberus_re_skill.modules.xpc_surface import build_xpc_surface


class XpcSurfaceTests(unittest.TestCase):
    def test_extension_point_identifiers_are_not_probable_services(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            objc = root / "objc.json"
            strings = root / "strings.json"
            symbols = root / "symbols.json"
            output = root / "xpc-surface.json"
            markdown = root / "xpc-surface.md"

            objc.write_text(json.dumps({"classes": [], "selectors": [], "protocols": []}), encoding="utf-8")
            strings.write_text(
                json.dumps(
                    {
                        "strings": [
                            {"value": "com.apple.ui-services", "address": "1000", "xref_count": 0},
                            {"value": "com.apple.intents-service", "address": "1008", "xref_count": 1},
                            {
                                "value": "com.apple.ManagedClient.agent",
                                "address": "1010",
                                "xref_count": 1,
                            },
                            {"value": "com.apple.example.helper.xpc", "address": "1018", "xref_count": 0},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            symbols.write_text(
                json.dumps(
                    {
                        "symbols": [
                            {
                                "name": "_OBJC_CLASS_$_NSXPCConnection",
                                "address": "EXTERNAL:1",
                                "symbol_type": "Label",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = build_xpc_surface(
                "proj",
                "Program",
                objc_metadata_path=objc,
                strings_path=strings,
                symbols_path=symbols,
                output=output,
                markdown_output=markdown,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertTrue(result["ok"])
        self.assertEqual(payload["summary"]["service_name_count"], 1)
        self.assertEqual(payload["service_names"][0]["value"], "com.apple.example.helper.xpc")
        hint_values = {item["value"] for item in payload["reverse_dns_service_hints"]}
        self.assertNotIn("com.apple.ui-services", hint_values)
        self.assertNotIn("com.apple.intents-service", hint_values)
        self.assertIn("com.apple.ManagedClient.agent", hint_values)


if __name__ == "__main__":
    unittest.main()
