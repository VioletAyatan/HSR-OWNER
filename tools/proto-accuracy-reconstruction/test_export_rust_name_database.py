import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("export_rust_name_database.py")
SPEC = importlib.util.spec_from_file_location("export_rust_name_database", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {SCRIPT}")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ExportRustNameDatabaseTests(unittest.TestCase):
    def write_fixture(self, directory, name, text):
        path = Path(directory, name)
        path.write_text(text, encoding="utf-8")
        return path

    def generate(self, raw_text, accepted_text):
        with tempfile.TemporaryDirectory() as directory:
            raw = self.write_fixture(directory, "raw.proto", raw_text)
            accepted = self.write_fixture(directory, "accepted.proto", accepted_text)
            raw_packets = self.write_fixture(directory, "raw.json", "{}\n")
            accepted_packets = self.write_fixture(directory, "accepted.json", "{}\n")
            return MODULE.generate(
                raw,
                accepted,
                raw_packets,
                accepted_packets,
                "unit-test",
            )

    def test_canonical_identity_not_declaration_order_binds_aliases(self):
        raw = """syntax = \"proto3\";
message AAAAAAAAAAA {
  uint32 CCCCCCCCCCC = 1;
}
message BBBBBBBBBBB {
  uint32 DDDDDDDDDDD = 1;
}
"""
        accepted = """syntax = \"proto3\";
// Obf: BBBBBBBBBBB
message ReadableB {
  uint32 b_value = 1;
}
// Obf: AAAAAAAAAAA
message ReadableA {
  uint32 a_value = 1;
}
"""
        manifest = self.generate(raw, accepted)
        records = {record["canonical"]: record for record in manifest["types"]}
        self.assertEqual(records["AAAAAAAAAAA"]["accepted_name"], "ReadableA")
        self.assertEqual(records["AAAAAAAAAAA"]["fields"][0]["accepted"], "a_value")
        self.assertEqual(records["BBBBBBBBBBB"]["accepted_name"], "ReadableB")
        self.assertEqual(records["BBBBBBBBBBB"]["fields"][0]["accepted"], "b_value")

    def test_nested_type_declaration_order_is_not_identity(self):
        raw = """syntax = \"proto3\";
message PPPPPPPPPPP {
  message AAAAAAAAAAA {
    uint32 CCCCCCCCCCC = 1;
  }
  message BBBBBBBBBBB {
    uint32 DDDDDDDDDDD = 1;
  }
  AAAAAAAAAAA EEEEEEEEEEE = 1;
  BBBBBBBBBBB FFFFFFFFFFF = 2;
}
"""
        accepted = """syntax = \"proto3\";
message PPPPPPPPPPP {
  message BBBBBBBBBBB {
    uint32 b_value = 1;
  }
  message AAAAAAAAAAA {
    uint32 a_value = 1;
  }
  AAAAAAAAAAA first = 1;
  BBBBBBBBBBB second = 2;
}
"""
        manifest = self.generate(raw, accepted)
        records = {record["canonical"]: record for record in manifest["types"]}
        self.assertEqual(
            records["PPPPPPPPPPP.AAAAAAAAAAA"]["fields"][0]["accepted"],
            "a_value",
        )
        self.assertEqual(
            records["PPPPPPPPPPP.BBBBBBBBBBB"]["fields"][0]["accepted"],
            "b_value",
        )

    def test_enum_declaration_order_is_bound_by_number(self):
        raw = """syntax = \"proto3\";
enum EEEEEEEEEEE {
  AAAAAAAAAAA = 1;
  BBBBBBBBBBB = 2;
}
"""
        accepted = """syntax = \"proto3\";
enum EEEEEEEEEEE {
  second_value = 2;
  first_value = 1;
}
"""
        manifest = self.generate(raw, accepted)
        record = next(
            record
            for record in manifest["types"]
            if record["canonical"] == "EEEEEEEEEEE"
        )
        variants = {variant["number"]: variant["accepted"] for variant in record["variants"]}
        self.assertEqual(variants, {1: "first_value", 2: "second_value"})

    def test_custom_inputs_do_not_inherit_wave10_approval(self):
        raw = """syntax = \"proto3\";
message AAAAAAAAAAA {
  uint32 BBBBBBBBBBB = 1;
}
"""
        accepted = """syntax = \"proto3\";
// Obf: AAAAAAAAAAA
message Readable {
  uint32 value = 1;
}
"""
        manifest = self.generate(raw, accepted)
        self.assertEqual(manifest["source"]["review_status"], "unreviewed")
        self.assertNotIn("independent_review_sha256", manifest["source"])


if __name__ == "__main__":
    unittest.main()
