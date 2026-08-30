import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cerberus_re_skill.modules.static_reliability import (
    APPLE_BUNDLE_FILES,
    APPLE_BUNDLE_MANIFEST,
    GHIDRA_SYMBOL_NAME_LIMIT,
    StaticReliabilityError,
    apple_bundle_staging,
    build_swift_symbol_sidecar,
    filter_expected_dyld_warnings,
    parse_overlength_swift_symbols,
    publish_apple_bundle,
    stable_swift_symbol_alias,
    summarize_import_diagnostics,
    validate_apple_bundle,
)


def write_staged_bundle(directory: Path, marker: str = "first") -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for name in APPLE_BUNDLE_FILES:
        (directory / name).write_text(
            json.dumps({"file": name, "marker": marker}) + "\n",
            encoding="utf-8",
        )


class AppleBundleReliabilityTests(unittest.TestCase):
    def test_publish_writes_complete_manifest_last_and_validates_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            staging = root / "staging"
            destination = root / "bundle"
            write_staged_bundle(staging)
            sidecar = destination / "swift_symbol_aliases.json"
            destination.mkdir()
            sidecar.write_text('{"preserved":true}\n', encoding="utf-8")

            manifest = publish_apple_bundle(staging, destination)
            validated = validate_apple_bundle(destination)

            self.assertEqual(manifest, validated)
            self.assertEqual(manifest["status"], "complete")
            self.assertTrue(manifest["bundle_id"].startswith("sha256:"))
            self.assertEqual([item["name"] for item in manifest["files"]], list(APPLE_BUNDLE_FILES))
            self.assertTrue(sidecar.exists())
            self.assertFalse(list(destination.glob(".*.tmp")))

    def test_missing_staged_file_never_changes_existing_complete_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            destination = root / "bundle"
            complete = root / "complete"
            partial = root / "partial"
            write_staged_bundle(complete, "old")
            old_manifest = publish_apple_bundle(complete, destination)
            old_bytes = (destination / "program_summary.json").read_bytes()
            write_staged_bundle(partial, "new")
            (partial / "strings.json").unlink()

            with self.assertRaisesRegex(StaticReliabilityError, "missing required file"):
                publish_apple_bundle(partial, destination)

            self.assertEqual(validate_apple_bundle(destination), old_manifest)
            self.assertEqual((destination / "program_summary.json").read_bytes(), old_bytes)

    def test_interrupted_publication_cannot_retain_complete_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            staging = root / "staging"
            destination = root / "bundle"
            write_staged_bundle(staging)

            with patch(
                "cerberus_re_skill.modules.static_reliability._atomic_copy",
                side_effect=OSError("simulated interruption"),
            ):
                with self.assertRaisesRegex(OSError, "simulated interruption"):
                    publish_apple_bundle(staging, destination)

            manifest = json.loads(
                (destination / APPLE_BUNDLE_MANIFEST).read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["status"], "publishing")
            with self.assertRaisesRegex(StaticReliabilityError, "not complete"):
                validate_apple_bundle(destination)

    def test_tampered_bundle_fails_manifest_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            staging = root / "staging"
            destination = root / "bundle"
            write_staged_bundle(staging)
            publish_apple_bundle(staging, destination)
            (destination / "symbols.json").write_text('{"tampered":true}\n', encoding="utf-8")

            with self.assertRaisesRegex(StaticReliabilityError, "do not match"):
                validate_apple_bundle(destination)

    def test_private_staging_directory_is_always_removed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "bundle"
            with self.assertRaisesRegex(RuntimeError, "stop"):
                with apple_bundle_staging(destination) as staging:
                    self.assertTrue(staging.is_dir())
                    raise RuntimeError("stop")
            self.assertFalse(staging.exists())


class SwiftSymbolReliabilityTests(unittest.TestCase):
    def test_overlength_swift_identity_has_stable_bounded_alias_and_full_sidecar(self) -> None:
        symbol = "_$s" + ("VeryLongSwiftIdentity" * 250)
        other = "_$s" + ("DifferentSwiftIdentity" * 250)
        nm_output = f"0000000000001000 T {symbol}\n0000000000002000 T {other}\n"

        parsed = parse_overlength_swift_symbols(nm_output)
        alias = stable_swift_symbol_alias(symbol)

        self.assertEqual(parsed, sorted([symbol, other]))
        self.assertLess(len(alias), GHIDRA_SYMBOL_NAME_LIMIT)
        self.assertEqual(alias, stable_swift_symbol_alias(symbol))
        self.assertNotEqual(alias, stable_swift_symbol_alias(other))

        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "Framework"
            binary.write_bytes(b"mach-o fixture")
            sidecar = build_swift_symbol_sidecar(
                binary,
                warning_count=2,
                nm_output=nm_output,
                nm_tool="/usr/bin/nm",
            )

        self.assertEqual(sidecar["status"], "complete")
        self.assertEqual(sidecar["preserved_symbol_count"], 2)
        self.assertEqual(sidecar["aliases"][1]["original_name"], symbol)
        self.assertEqual(sidecar["aliases"][1]["original_length"], len(symbol))
        self.assertEqual(sidecar["aliases"][1]["stable_alias"], alias)

    def test_sidecar_records_unavailable_static_symbol_tool(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "Framework"
            binary.write_bytes(b"fixture")
            sidecar = build_swift_symbol_sidecar(
                binary,
                warning_count=1,
                nm_output=None,
                error="nm was not found on PATH",
            )

        self.assertEqual(sidecar["status"], "unavailable")
        self.assertEqual(sidecar["preserved_symbol_count"], 0)
        self.assertIn("not found", sidecar["error"])


class DyldDiagnosticReliabilityTests(unittest.TestCase):
    def test_expected_dependency_lines_are_aggregated_while_unknowns_remain_visible(self) -> None:
        system = "/System/Library/Frameworks/Foundation.framework/Foundation"
        private = "/System/Library/PrivateFrameworks/ExamplePrivate.framework/ExamplePrivate"
        swift = "/usr/lib/swift/libswiftCore.dylib"
        other = "@rpath/OwnedDependency.framework/OwnedDependency"
        lines = (
            f"INFO [{system}] -> not found in project\n"
            f"INFO [{system}] -> not found in project\n"
            f"WARN [{private}] -> not found in project\n"
            f"WARN [{swift}] -> not found in project\n"
            f"WARN [{other}] -> not found in project\n"
            "analysis complete\n"
            "Unable to create symbol: Symbol name exceeds maximum length of 2000, length=5009\n"
        )

        filtered, suppressed = filter_expected_dyld_warnings(lines)
        summary = summarize_import_diagnostics(lines, "Unable to demangle: _$sExample\n")

        self.assertEqual(suppressed, 4)
        self.assertNotIn(system, filtered)
        self.assertIn(other, filtered)
        self.assertIn("analysis complete", filtered)
        self.assertEqual(summary["unresolved_count"], 5)
        self.assertEqual(summary["unresolved_unique_count"], 4)
        self.assertEqual(summary["expected_unresolved_count"], 4)
        self.assertEqual(summary["unresolved_system"], 2)
        self.assertEqual(summary["unresolved_groups"]["system"]["unique_count"], 1)
        self.assertEqual(summary["symbol_length_failures"], 1)
        self.assertEqual(summary["demangle_failures"], 1)


if __name__ == "__main__":
    unittest.main()
