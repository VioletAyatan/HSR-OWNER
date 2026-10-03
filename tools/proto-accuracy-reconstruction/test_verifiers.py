import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import proto_document
import reconstruct_accuracy_proto as reconstruction
import publication_lock

TOOLS = Path(__file__).resolve().parent
PROJECT = TOOLS.parents[1]
SOURCE_RUN = PROJECT / "target/allocator-fh3-runtime-20261003-041926"
VERIFIER = TOOLS / "verify_accuracy_artifacts.py"
ACCEPTED = TOOLS / "accepted-2026-10-03.json"
REQUIRED = [
    "StarRail.compat.proto",
    "StarRail.accuracy.proto",
    "packetIds.json",
    "accuracy-reconstruction-report.json",
    "derived-compatibility-validation.json",
    "accuracy-sourceparse-validation.json",
    "accuracy-publication.json",
]


def file_sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class VerifierFailClosedTests(unittest.TestCase):
    def make_fixture(self):
        temporary = tempfile.TemporaryDirectory()
        run = Path(temporary.name)
        for name in REQUIRED:
            shutil.copy2(SOURCE_RUN / name, run / name)
        accepted = run / "accepted.json"
        shutil.copy2(ACCEPTED, accepted)
        return temporary, run, accepted

    def invoke(self, run: Path, accepted: Path, optimized: bool = False):
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.append(str(VERIFIER))
        env = os.environ.copy()
        env["HSR_OWNER_ROOT"] = str(PROJECT)
        env["HSR_PROTO_RUN"] = str(run)
        env["HSR_PROTO_ACCEPTED"] = str(accepted)
        return subprocess.run(command, env=env, capture_output=True, text=True)

    def test_rejects_accepted_hash_mismatch(self):
        temporary, run, accepted = self.make_fixture()
        with temporary:
            data = json.loads(accepted.read_text(encoding="utf-8"))
            data["accuracy_proto_sha256"] = "0" * 64
            accepted.write_text(json.dumps(data), encoding="utf-8")
            result = self.invoke(run, accepted)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_optimized_python_cannot_bypass_artifact_mismatch(self):
        temporary, run, accepted = self.make_fixture()
        with temporary:
            proto = run / "StarRail.accuracy.proto"
            source = proto.read_text(encoding="utf-8")
            self.assertIn("player_outfit_data", source)
            proto.write_text(source.replace("player_outfit_data", "player_outfit_data_x", 1), encoding="utf-8")
            data = json.loads(accepted.read_text(encoding="utf-8"))
            data["accuracy_proto_sha256"] = file_sha256(proto)
            accepted.write_text(json.dumps(data), encoding="utf-8")
            result = self.invoke(run, accepted, optimized=True)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_rejects_packet_mapping_content_change(self):
        temporary, run, accepted = self.make_fixture()
        with temporary:
            packet_path = run / "packetIds.json"
            packets = json.loads(packet_path.read_text(encoding="utf-8-sig"))
            packets["1281"] = "PlayerSimpleInfo"
            packet_path.write_text(json.dumps(packets), encoding="utf-8")
            result = self.invoke(run, accepted)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_rejects_enum_as_packet_target_even_when_packet_hash_is_updated(self):
        temporary, run, accepted = self.make_fixture()
        with temporary:
            packet_path = run / "packetIds.json"
            packets = json.loads(packet_path.read_text(encoding="utf-8-sig"))
            packets["1281"] = "PlayerActionType"
            packet_path.write_text(json.dumps(packets), encoding="utf-8")
            data = json.loads(accepted.read_text(encoding="utf-8"))
            data["packet_ids_sha256"] = file_sha256(packet_path)
            accepted.write_text(json.dumps(data), encoding="utf-8")
            result = self.invoke(run, accepted)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_rejects_fabricated_reference_provenance(self):
        temporary, run, accepted = self.make_fixture()
        with temporary:
            report_path = run / "accuracy-reconstruction-report.json"
            report = json.loads(report_path.read_text(encoding="utf-8-sig"))
            report["reference_commit"] = "0" * 40
            report["reference_commit_blob_oid"] = "1" * 40
            report["reference_worktree_blob_oid"] = "1" * 40
            report_path.write_text(json.dumps(report), encoding="utf-8")
            publication_path = run / "accuracy-publication.json"
            publication = json.loads(publication_path.read_text(encoding="utf-8-sig"))
            publication["reconstruction_report_sha256"] = file_sha256(report_path)
            publication_path.write_text(json.dumps(publication), encoding="utf-8")
            result = self.invoke(run, accepted)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_parser_reports_duplicate_enum_variant_names(self):
        with tempfile.TemporaryDirectory() as directory:
            proto = Path(directory) / "duplicate.proto"
            proto.write_text(
                'syntax = "proto3";\n'
                "enum Example {\n"
                "  DUP = 0;\n"
                "  DUP = 1;\n"
                "}\n",
                encoding="utf-8",
            )
            parsed = proto_document.parse(proto)
            self.assertIn(("duplicate enum variant", "Example", "DUP"), parsed["errors"])

    def test_parser_reports_duplicate_displayed_types_in_one_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            proto = Path(directory) / "duplicate-types.proto"
            proto.write_text(
                'syntax = "proto3";\n'
                "// Obf: AAAAAAAAAAA\n"
                "message Dup {\n}\n"
                "// Obf: BBBBBBBBBBB\n"
                "message Dup {\n}\n",
                encoding="utf-8",
            )
            parsed = proto_document.parse(proto)
            self.assertIn(("duplicate displayed type", None, "Dup"), parsed["errors"])

    def test_pairwise_proposed_message_name_collision_is_rejected(self):
        def message(name, fields=None):
            return {
                "kind": "message",
                "name": name,
                "display": name,
                "parent": None,
                "children": [],
                "fields": fields or [],
                "oneofs": [],
                "variants": [],
                "metadata": {},
            }

        current_items = {
            "AAAAAAAAAAA": message("AAAAAAAAAAA"),
            "BBBBBBBBBBB": message("BBBBBBBBBBB"),
        }
        reference_items = {
            "ExternalA": message("Dup"),
            "ExternalB": message("Dup"),
        }
        mapping = {"AAAAAAAAAAA": "ExternalA", "BBBBBBBBBBB": "ExternalB"}
        proofs = {}
        for index, target in enumerate(("AAAAAAAAAAA", "AAAAAAAAAAA", "BBBBBBBBBBB", "BBBBBBBBBBB")):
            owner = f"ROOT{index:07d}"
            external_owner = f"ExternalRoot{index}"
            external_target = mapping[target]
            current_items[owner] = message(owner, [{
                "tag": 1, "name": "value", "kind": target, "normalized_kind": target, "offset": 0,
            }])
            reference_items[external_owner] = message(external_owner, [{
                "tag": 1, "name": "value", "kind": external_target,
                "normalized_kind": external_target, "offset": 0,
            }])
            mapping[owner] = external_owner
            proofs[owner] = {"source": "same-canonical-identity"}
        proofs["AAAAAAAAAAA"] = {"source": "mapped-owner-field-type-edge"}
        proofs["BBBBBBBBBBB"] = {"source": "mapped-owner-field-type-edge"}
        current = {"items": current_items, "aliases": {}}
        reference = {"items": reference_items, "aliases": {}}

        accepted, rejected = reconstruction.strict_graph_message_type_names(
            current, reference, mapping, proofs
        )
        self.assertEqual(1, len(accepted))
        self.assertEqual(1, len(rejected))
        self.assertEqual("candidate-name-collision", rejected[0]["reason"])

    def test_atomic_writer_does_not_follow_predictable_temp_hardlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            victim = root / "victim.txt"
            victim.write_bytes(b"protected")
            destination = root / "artifact.json"
            predictable_temp = destination.with_suffix(destination.suffix + ".tmp")
            os.link(victim, predictable_temp)

            reconstruction.atomic_write_bytes(destination, b"published")

            self.assertEqual(b"protected", victim.read_bytes())
            self.assertEqual(b"protected", predictable_temp.read_bytes())
            self.assertEqual(b"published", destination.read_bytes())

    def test_rejects_missing_publication_marker(self):
        temporary, run, accepted = self.make_fixture()
        with temporary:
            (run / "accuracy-publication.json").unlink()
            result = self.invoke(run, accepted)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_verifier_result_does_not_follow_existing_hardlink(self):
        temporary, run, accepted = self.make_fixture()
        with temporary:
            victim = run / "victim.txt"
            victim.write_bytes(b"protected")
            result_path = run / "accuracy-artifact-checks.json"
            os.link(victim, result_path)
            result = self.invoke(run, accepted)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertEqual(b"protected", victim.read_bytes())
            self.assertNotEqual(os.stat(victim).st_ino, os.stat(result_path).st_ino)

    def test_publication_lock_blocks_a_second_process(self):
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / "publication.lock"
            child_code = (
                "import sys; from pathlib import Path; "
                f"sys.path.insert(0, {str(TOOLS)!r}); "
                "from publication_lock import exclusive_lock; "
                f"lock=Path({str(lock_path)!r}); "
                "\nwith exclusive_lock(lock, timeout=5):\n print('acquired', flush=True)"
            )
            with publication_lock.exclusive_lock(lock_path, timeout=5):
                child = subprocess.Popen(
                    [sys.executable, "-c", child_code],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                import time
                time.sleep(0.3)
                self.assertIsNone(child.poll())
            stdout, stderr = child.communicate(timeout=10)
            self.assertEqual(0, child.returncode, stdout + stderr)
            self.assertIn("acquired", stdout)

    def test_publication_lock_rejects_multiple_hardlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock_path = root / "publication.lock"
            lock_path.write_bytes(b"\0")
            os.link(lock_path, root / "alias.lock")
            with self.assertRaises(publication_lock.PublicationLockError):
                with publication_lock.exclusive_lock(lock_path, timeout=0.1):
                    self.fail("multiply linked lock unexpectedly acquired")

    def test_publication_lock_rejects_static_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.lock"
            target.write_bytes(b"\0")
            lock_path = root / "publication.lock"
            try:
                lock_path.symlink_to(target)
            except OSError as error:
                self.skipTest(f"symlink creation unavailable: {error}")
            with self.assertRaises(publication_lock.PublicationLockError):
                with publication_lock.exclusive_lock(lock_path, timeout=0.1):
                    self.fail("symlink lock unexpectedly acquired")

    def test_publication_lock_revalidates_path_identity_after_acquisition(self):
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / "publication.lock"
            lock_path.write_bytes(b"\0")
            real_lstat = publication_lock.os.lstat
            calls = 0

            def replaced_path(path):
                nonlocal calls
                metadata = real_lstat(path)
                calls += 1
                if calls < 2:
                    return metadata
                return types.SimpleNamespace(
                    st_mode=metadata.st_mode,
                    st_nlink=metadata.st_nlink,
                    st_dev=metadata.st_dev,
                    st_ino=metadata.st_ino + 1,
                )

            with mock.patch.object(publication_lock.os, "lstat", replaced_path):
                with self.assertRaises(publication_lock.PublicationLockError):
                    with publication_lock.exclusive_lock(lock_path, timeout=0.1):
                        self.fail("replaced lock pathname unexpectedly accepted")

    def test_publication_preparation_failure_preserves_previous_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact.proto"
            report = root / "report.json"
            marker = root / "publication.json"
            artifact.write_bytes(b"old-artifact")
            report.mkdir()
            marker.write_bytes(b"old-marker")

            with self.assertRaises((IsADirectoryError, PermissionError)):
                reconstruction.publish_generation(
                    artifact, b"new-artifact", report, b"new-report", marker
                )

            self.assertEqual(b"old-artifact", artifact.read_bytes())
            self.assertEqual(b"old-marker", marker.read_bytes())
            self.assertFalse(list(root.glob(".*.tmp")))

    def test_publication_failure_rolls_back_artifact_report_and_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact.proto"
            report = root / "report.json"
            marker = root / "publication.json"
            artifact.write_bytes(b"old-artifact")
            report.write_bytes(b"old-report")
            marker.write_bytes(b"old-marker")
            real_replace = os.replace
            failed = False

            def fail_first_report_replace(source, destination):
                nonlocal failed
                if Path(destination) == report and not failed:
                    failed = True
                    raise OSError("injected report publication failure")
                return real_replace(source, destination)

            with mock.patch.object(reconstruction.os, "replace", fail_first_report_replace):
                with self.assertRaisesRegex(OSError, "injected"):
                    reconstruction.publish_generation(
                        artifact, b"new-artifact", report, b"new-report", marker
                    )

            self.assertEqual(b"old-artifact", artifact.read_bytes())
            self.assertEqual(b"old-report", report.read_bytes())
            self.assertEqual(b"old-marker", marker.read_bytes())


if __name__ == "__main__":
    unittest.main()
