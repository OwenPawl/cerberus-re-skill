import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cerberus_re_skill.modules.nsxpc_interface_config import (
    NSXPC_INTERFACE_CONFIG_SCHEMA,
    export_nsxpc_interface_config,
)


class NSXPCInterfaceConfigTests(unittest.TestCase):
    def test_export_uses_factory_report_functions_and_writes_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "config.json"
            markdown = root / "config.md"
            factory = root / "factory.json"
            factory.write_text(
                json.dumps(
                    {
                        "factories": [
                            {
                                "target": "proj:Program",
                                "function": {"name": "_ExampleUIPresenterXPCInterface"},
                            },
                            {
                                "target": "other:Program",
                                "function": {"name": "_OtherXPCInterface"},
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            seen: dict[str, object] = {}

            def fake_run_script(script: str, project: str, program: str, script_args: list[str]) -> dict:
                seen.update({"script": script, "project": project, "program": program, "script_args": script_args})
                output.write_text(
                    json.dumps(
                        {
                            "schema": NSXPC_INTERFACE_CONFIG_SCHEMA,
                            "ok": True,
                            "project_name": project,
                            "program_name": program,
                            "summary": {
                                "function_count": 1,
                                "pattern_function_count": 1,
                                "allowed_class_call_count": 1,
                                "interface_with_protocol_call_count": 1,
                                "protocol_reference_count": 1,
                            },
                            "functions": [
                                {
                                    "function": "_ExampleUIPresenterXPCInterface",
                                    "entry": "0x1000",
                                    "selection_reasons": ["explicit:function"],
                                    "protocol_references": ["ExampleUIPresenterInterface"],
                                    "allowed_class_call_count": 1,
                                    "interface_with_protocol_call_count": 1,
                                    "allowed_class_calls": [
                                        {
                                            "selector": "setClasses:forSelector:argumentIndex:ofReply:",
                                            "line_number": 12,
                                        }
                                    ],
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                return {"ok": True, "script_name": script}

            with patch("cerberus_re_skill.modules.importer.run_script", side_effect=fake_run_script):
                result = export_nsxpc_interface_config(
                    "proj",
                    "Program",
                    factory_report=factory,
                    functions=["_ExplicitConfig"],
                    output=output,
                    markdown_output=markdown,
                    limit=9,
                    timeout=17,
                )
            markdown_text = markdown.read_text(encoding="utf-8")

        self.assertTrue(result["ok"])
        self.assertEqual(seen["script"], "ExportNSXPCInterfaceConfig.java")
        self.assertIn("function=_ExplicitConfig", seen["script_args"])
        self.assertIn("function=_ExampleUIPresenterXPCInterface", seen["script_args"])
        self.assertIn("limit=9", seen["script_args"])
        self.assertIn("timeout=17", seen["script_args"])
        self.assertEqual(result["pattern_function_count"], 1)
        self.assertIn("ExampleUIPresenterInterface", markdown_text)


if __name__ == "__main__":
    unittest.main()
