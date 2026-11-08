import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase

import study_pulse_crypto as study


class StudyPulseWebsiteTests(SimpleTestCase):
	def setUp(self):
		self.temp_dir = tempfile.TemporaryDirectory()
		storage = Path(self.temp_dir.name)
		self.patches = [
			patch.object(study, "KEY_FILE", storage / "key.bin"),
			patch.object(study, "DATA_FILE", storage / "note.json"),
			patch.object(study, "BORROW_FILE", storage / "borrows.json"),
			patch.object(study, "NOTIFICATIONS_FILE", storage / "notifications.json"),
		]
		for patcher in self.patches:
			patcher.start()

	def tearDown(self):
		for patcher in reversed(self.patches):
			patcher.stop()
		self.temp_dir.cleanup()

	def test_note_encryption_and_decryption_through_website(self):
		response = self.client.post("/", {"action": "encrypt", "study_note": "Private test note"})
		self.assertContains(response, "encrypted and saved")
		stored_data = json.loads(study.DATA_FILE.read_text(encoding="utf-8"))
		self.assertEqual(set(stored_data), {"nonce", "ciphertext"})
		self.assertNotIn("Private test note", study.DATA_FILE.read_text(encoding="utf-8"))

		response = self.client.post("/", {"action": "decrypt"})
		self.assertContains(response, "Private test note")
		self.assertContains(response, "integrity verification succeeded")

	def test_tampering_is_reported_as_integrity_failure(self):
		study.encrypt_note("Tamper test note", study.load_or_create_key())
		self.client.post("/", {"action": "tamper_test"})

		response = self.client.post("/", {"action": "decrypt", "active_view": "tamper-view"})

		self.assertContains(response, "Integrity failure")
		self.assertEqual(response.context["integrity_status"], "Integrity failure")
		self.assertEqual(response.context["active_view"], "tamper-view")

	def test_borrow_search_and_return_through_website(self):
		response = self.client.post(
			"/",
			{"action": "borrow", "item_name": "Cryptography Handbook", "student_id": "STU-1"},
		)
		self.assertContains(response, "Borrow request submitted")
		record = study._read_json_list(study.BORROW_FILE)[0]

		response = self.client.post("/", {"action": "search", "keyword": "handbook"})
		self.assertContains(response, "Cryptography Handbook")

		response = self.client.post("/", {"action": "return", "record_id": record["id"]})
		self.assertContains(response, "Returned Cryptography Handbook")
		self.assertEqual(study._read_json_list(study.BORROW_FILE)[0]["status"], "returned")

	def test_empty_note_shows_validation_message(self):
		response = self.client.post("/", {"action": "encrypt", "study_note": "   "})
		self.assertContains(response, "empty notes are not saved")
