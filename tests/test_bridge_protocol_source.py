import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
JAVA_ROOT = (
    REPO_ROOT
    / "bridge-extension"
    / "CodexGhidraBridge"
    / "src"
    / "main"
    / "java"
    / "codexghidrabridge"
)


class BridgeProtocolSourceTests(unittest.TestCase):
    def test_all_program_operations_resolve_the_request_body(self) -> None:
        read_support = (JAVA_ROOT / "CodexBridgeReadSupport.java").read_text(encoding="utf-8")
        mutation_support = (JAVA_ROOT / "CodexBridgeMutationSupport.java").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("requireProgram()", read_support)
        self.assertNotIn("requireProgram()", mutation_support)
        self.assertGreaterEqual(read_support.count("requireProgram(body)"), 15)
        self.assertIn("Program program = requireProgram(body);", mutation_support)

    def test_v2_identity_and_inventory_are_published(self) -> None:
        identity = (JAVA_ROOT / "CodexBridgeIdentity.java").read_text(encoding="utf-8")
        service = (JAVA_ROOT / "CodexBridgeService.java").read_text(encoding="utf-8")
        frontend = (JAVA_ROOT / "CodexBridgeFrontEndPlugin.java").read_text(encoding="utf-8")
        self.assertIn('SCHEMA_VERSION = "cerberus.bridge.v2"', identity)
        self.assertIn('"executable_sha256"', identity)
        self.assertIn('"open_programs"', identity)
        self.assertIn('session.addProperty("version", 2)', service)
        self.assertIn('"/inventory"', service)
        self.assertIn("writeApplicationInventory", frontend)

    def test_non_current_navigation_requires_explicit_activation(self) -> None:
        read_support = (JAVA_ROOT / "CodexBridgeReadSupport.java").read_text(encoding="utf-8")
        self.assertIn('optBoolean(body, "activate", false)', read_support)
        self.assertIn('pass activate=true to change the selected program', read_support)

    def test_frontend_opens_into_an_explicit_tool_without_selecting(self) -> None:
        frontend = (JAVA_ROOT / "CodexBridgeFrontEndPlugin.java").read_text(encoding="utf-8")
        self.assertIn('optString(request, "tool_id")', frontend)
        self.assertIn(
            "manager.openProgram(domainFile, DomainFile.DEFAULT_VERSION,",
            frontend,
        )
        self.assertIn("ProgramManager.OPEN_VISIBLE", frontend)
        self.assertIn("findRunningToolById", frontend)
        self.assertIn("requestedApplicationId", frontend)
        self.assertIn("CodexBridgeIdentity.applicationId()", frontend)

    def test_every_mutation_and_save_gets_an_immutable_operation_record(self) -> None:
        mutation = (JAVA_ROOT / "CodexBridgeMutationSupport.java").read_text(
            encoding="utf-8"
        )
        read_support = (JAVA_ROOT / "CodexBridgeReadSupport.java").read_text(
            encoding="utf-8"
        )
        self.assertIn("if (mutation != null)", mutation)
        self.assertNotIn("if (destructive && mutation != null)", mutation)
        self.assertIn('"cerberus.bridge.operation.v2"', mutation)
        self.assertIn('writeOperationLog(program, "program-save", body, mutation)', read_support)


if __name__ == "__main__":
    unittest.main()
