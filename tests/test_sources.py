import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.modules.sources import add_source, list_sources, resolve_source


class SourceRegistryTests(unittest.TestCase):
    def test_add_and_list_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = Path(tmp) / "sources.json"
            root = Path(tmp) / "root"
            root.mkdir()
            with patch.object(cfg, "source_registry_file", registry):
                result = add_source("mac-image", root, platform="macos-image", copy="direct")
                listed = list_sources()

        self.assertTrue(result["ok"])
        self.assertEqual(listed["sources"][0]["name"], "mac-image")
        self.assertEqual(listed["sources"][0]["copy"], "direct")

    def test_resolve_source_file_uses_backend(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = Path(tmp) / "sources.json"
            cache = Path(tmp) / "cache"
            root = Path(tmp) / "root"
            binary = root / "System/Library/PrivateFrameworks/Demo.framework/Demo"
            binary.parent.mkdir(parents=True)
            binary.write_text("demo", encoding="utf-8")
            with (
                patch.object(cfg, "source_registry_file", registry),
                patch.object(cfg, "sources_cache_dir", cache),
            ):
                add_source("mac-image", root, copy="cache")
                result = resolve_source("mac-image", "/System/Library/PrivateFrameworks/Demo.framework/Demo")

                self.assertTrue(result["ok"])
                resolved = Path(result["resolution"]["resolved_path"])
                self.assertTrue(resolved.exists())
                self.assertIn("mac-image", str(resolved))

    def test_resolve_source_no_extract_stops_before_dyld_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = Path(tmp) / "sources.json"
            cache = Path(tmp) / "cache"
            root = Path(tmp) / "root"
            dyld_cache = root / "System/Library/dyld/dyld_shared_cache_arm64e"
            dyld_cache.parent.mkdir(parents=True)
            dyld_cache.write_text("cache", encoding="utf-8")
            with (
                patch.object(cfg, "source_registry_file", registry),
                patch.object(cfg, "sources_cache_dir", cache),
            ):
                add_source("mac-image", root, copy="cache")
                with self.assertRaisesRegex(RuntimeError, "would require dyld cache extraction"):
                    resolve_source(
                        "mac-image",
                        "/System/Library/PrivateFrameworks/Demo.framework/Demo",
                        no_extract=True,
                    )

    def test_resolve_source_no_extract_allows_existing_extracted_copy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = Path(tmp) / "sources.json"
            cache = Path(tmp) / "cache"
            root = Path(tmp) / "root"
            dyld_cache = root / "System/Library/dyld/dyld_shared_cache_arm64e"
            dyld_cache.parent.mkdir(parents=True)
            dyld_cache.write_text("cache", encoding="utf-8")
            with (
                patch.object(cfg, "source_registry_file", registry),
                patch.object(cfg, "sources_cache_dir", cache),
            ):
                add_source("mac-image", root, copy="cache")
                cache_identity = hashlib.sha256(
                    f"{dyld_cache}:{dyld_cache.stat().st_size}:{dyld_cache.stat().st_mtime_ns}".encode("utf-8")
                ).hexdigest()[:16]
                extracted = (
                    cache
                    / "mac-image"
                    / "_dyld_extract"
                    / cache_identity
                    / "root"
                    / "System/Library/PrivateFrameworks/Demo.framework/Versions/A/Demo"
                )
                extracted.parent.mkdir(parents=True)
                extracted.write_text("demo", encoding="utf-8")

                result = resolve_source(
                    "mac-image",
                    "/System/Library/PrivateFrameworks/Demo.framework/Demo",
                    no_extract=True,
                )

        self.assertEqual(result["resolution"]["strategy"], "dyld-extract-existing")
        self.assertEqual(Path(result["resolution"]["resolved_path"]), extracted)

    def test_list_sources_recovers_trailing_garbage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = Path(tmp) / "sources.json"
            registry.write_text(
                '{"version": 1, "sources": [{"name": "mac-image", "root": "/tmp/root"}]}\n'
                '"trailing": "fragment"\n',
                encoding="utf-8",
            )
            with patch.object(cfg, "source_registry_file", registry):
                listed = list_sources()

        self.assertEqual(listed["sources"][0]["name"], "mac-image")

    def test_list_sources_accepts_legacy_list_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = Path(tmp) / "sources.json"
            registry.write_text('[{"name": "legacy", "root": "/tmp/root"}]\n', encoding="utf-8")
            with patch.object(cfg, "source_registry_file", registry):
                listed = list_sources()

        self.assertEqual(listed["sources"][0]["name"], "legacy")


if __name__ == "__main__":
    unittest.main()
