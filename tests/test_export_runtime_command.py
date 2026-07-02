import unittest

from cerberus_re_skill.commands.export_runtime import _mapping_summary


class ExportRuntimeCommandTests(unittest.TestCase):
    def test_mapping_summary_distinguishes_clean_matches_from_address_mapping(self) -> None:
        self.assertEqual(
            _mapping_summary(
                {
                    "hit_count": 3,
                    "matched_function_count": 0,
                    "address_mapped_function_count": 3,
                }
            ),
            "matched=0/3, address-mapped=3/3",
        )

    def test_mapping_summary_reports_symbol_evidence_for_boundary_conflicts(self) -> None:
        self.assertEqual(
            _mapping_summary(
                {
                    "hit_count": 3,
                    "matched_function_count": 1,
                    "address_mapped_function_count": 3,
                    "address_or_symbol_evidence_count": 3,
                }
            ),
            "evidence=3/3, matched=1/3, address-mapped=3/3",
        )

    def test_mapping_summary_keeps_legacy_clean_match_text(self) -> None:
        self.assertEqual(
            _mapping_summary(
                {
                    "hit_count": 3,
                    "matched_function_count": 3,
                    "address_mapped_function_count": 3,
                }
            ),
            "3/3 hits mapped",
        )


if __name__ == "__main__":
    unittest.main()
