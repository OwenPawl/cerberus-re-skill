import json
import tempfile
import unittest
from pathlib import Path

from cerberus_re_skill.modules.runtime_hits import (
    normalize_frida_console_hits,
    normalize_lldb_trace_hits,
    write_runtime_hits_artifact,
)


class RuntimeHitsTests(unittest.TestCase):
    def test_normalize_lldb_trace_hits_preserves_shared_fields(self) -> None:
        trace = {
            "hit_count": 1,
            "slide": "0x1000",
            "hits": [
                {
                    "pc": "0x2000",
                    "symbol": "-[CodexProbe runWithInput:]",
                    "registers": {"x0": "0xabc", "x1": "0xdef"},
                    "self_class": "CodexProbe",
                    "selector": "runWithInput:",
                    "backtrace": ["frame 0"],
                }
            ],
        }

        hits = normalize_lldb_trace_hits(trace, project="proj", program="Program", source_artifact="/tmp/lldb.json")

        self.assertEqual(len(hits), 1)
        hit = hits[0]
        self.assertEqual(hit["schema"], "ghidra-re.runtime-hit.v1")
        self.assertEqual(hit["tool"], "lldb")
        self.assertEqual(hit["target"]["project_name"], "proj")
        self.assertEqual(hit["runtime"]["pc"], "0x2000")
        self.assertEqual(hit["args"]["x0"], "0xabc")
        self.assertEqual(hit["objc"]["self_class"], "CodexProbe")
        self.assertEqual(hit["objc"]["selector"], "runWithInput:")

    def test_write_runtime_hits_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "runtime_hits.json"
            payload = write_runtime_hits_artifact(
                path,
                project="proj",
                program="Program",
                hits=[{"tool": "lldb"}],
                source="/tmp/lldb.json",
            )

            self.assertEqual(payload["schema"], "ghidra-re.runtime-hits.v1")
            self.assertEqual(payload["hit_count"], 1)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["tools"], ["lldb"])

    def test_normalize_frida_console_hits(self) -> None:
        text = (
            'noise\n'
            'GHIDRA_FRIDA_HIT {"symbol":"-[CodexProbe runWithInput:]","pc":"0x1000","module_base":"0x180000000","runtime":{"module":{"name":"CodexProbe","base":"0x180000000"}},"target":{"class_name":"CodexProbe"}}\n'
            'GHIDRA_FRIDA_RETURN {"symbol":"-[CodexProbe runWithInput:]","return_value":"0x1200"}\n'
            'GHIDRA_FRIDA_HEAP_OBJECT {"class_name":"CodexProbe","pointer":"0x2000"}\n'
        )

        hits = normalize_frida_console_hits(text, project="proj", program="Program", source_artifact="/tmp/frida.js")

        self.assertEqual(len(hits), 3)
        self.assertEqual(hits[0]["schema"], "ghidra-re.runtime-hit.v1")
        self.assertEqual(hits[0]["tool"], "frida")
        self.assertEqual(hits[0]["event_type"], "objc-call")
        self.assertEqual(hits[0]["target"]["project_name"], "proj")
        self.assertEqual(hits[0]["runtime"]["pc"], "0x1000")
        self.assertEqual(hits[0]["module_base"], "0x180000000")
        self.assertEqual(hits[0]["runtime"]["module"]["name"], "CodexProbe")
        self.assertEqual(hits[1]["event_type"], "objc-return")
        self.assertEqual(hits[2]["event_type"], "objc-heap-object")


if __name__ == "__main__":
    unittest.main()
