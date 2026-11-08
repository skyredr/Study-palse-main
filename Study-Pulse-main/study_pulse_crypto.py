import json
import os
import uuid
from datetime import date, datetime, timedelta
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Change these values to move or rename the local data files.
STORAGE_DIR = Path(__file__).resolve().parent
KEY_FILE = STORAGE_DIR / "study_pulse.key"
DATA_FILE = STORAGE_DIR / "encrypted_study_note.json"
BORROW_FILE = STORAGE_DIR / "borrow_records.json"
NOTIFICATIONS_FILE = STORAGE_DIR / "notifications.json"


class IntegrityFailure(Exception):
    """Raised when AES-GCM cannot authenticate the key and stored data."""


def load_or_create_key():
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()

    key = AESGCM.generate_key(bit_length=256)
    KEY_FILE.write_bytes(key)
    return key


def encrypt_note(note, key):
    if not note.strip():
        raise ValueError("Please enter a study note; empty notes are not saved.")

    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, note.encode("utf-8"), None)
    encrypted_record = {"nonce": nonce.hex(), "ciphertext": ciphertext.hex()}
    DATA_FILE.write_text(json.dumps(encrypted_record, indent=2), encoding="utf-8")
    return encrypted_record


def decrypt_note(encrypted_record, key):
    try:
        nonce = bytes.fromhex(encrypted_record["nonce"])
        ciphertext = bytes.fromhex(encrypted_record["ciphertext"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("Encrypted data is missing or has an invalid JSON format.") from error

    if len(key) != 32:
        raise IntegrityFailure("Integrity failure: the AES-256 key is invalid.")

    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag as error:
        raise IntegrityFailure(
            "Integrity failure: the key is incorrect or encrypted data was altered."
        ) from error
    return plaintext.decode("utf-8")


def tamper_test():
    if not DATA_FILE.exists():
        raise FileNotFoundError("Encrypt a study note before running the tamper test.")

    encrypted_record = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    ciphertext = bytearray(bytes.fromhex(encrypted_record["ciphertext"]))
    if not ciphertext:
        raise ValueError("The stored ciphertext is empty and cannot be altered.")

    ciphertext[0] ^= 1
    encrypted_record["ciphertext"] = ciphertext.hex()
    DATA_FILE.write_text(json.dumps(encrypted_record, indent=2), encoding="utf-8")


def _read_json_list(file_path):
    if not file_path.exists():
        return []
    data = json.loads(file_path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{file_path.name} must contain a JSON list.")
    return data


def _write_json_list(file_path, records):
    file_path.write_text(json.dumps(records, indent=2), encoding="utf-8")


def add_notification(message):
    notifications = _read_json_list(NOTIFICATIONS_FILE)
    timestamped_message = f"{datetime.now().astimezone().isoformat(timespec='minutes')}: {message}"
    notifications.append(timestamped_message)
    _write_json_list(NOTIFICATIONS_FILE, notifications)


def show_notifications():
    notifications = _read_json_list(NOTIFICATIONS_FILE)
    if not notifications:
        print("No notifications yet.")
        return
    for notification in notifications:
        print(f"- {notification}")


def request_borrow(item_name, student_id):
    if not item_name.strip() or not student_id.strip():
        raise ValueError("Both an item name and student ID are required.")

    records = _read_json_list(BORROW_FILE)
    record = {
        "id": uuid.uuid4().hex[:8],
        "item": item_name.strip(),
        "student_id": student_id.strip(),
        "status": "borrowed",
        "borrowed_on": date.today().isoformat(),
        "due_date": (date.today() + timedelta(days=14)).isoformat(),
        "overdue_notified": False,
    }
    records.append(record)
    _write_json_list(BORROW_FILE, records)
    add_notification(f"Borrow request submitted for {record['item']} (record {record['id']}).")
    return record


def return_borrow(record_id):
    records = _read_json_list(BORROW_FILE)
    for record in records:
        if record.get("id", "").casefold() == record_id.strip().casefold():
            if record.get("status") != "borrowed":
                raise ValueError("That item has already been returned.")
            record["status"] = "returned"
            record["returned_on"] = date.today().isoformat()
            _write_json_list(BORROW_FILE, records)
            add_notification(f"Item returned: {record.get('item', 'unknown item')}.")
            return record
    raise ValueError("No borrowed item matched that record ID.")


def check_overdue_reminders():
    records = _read_json_list(BORROW_FILE)
    today = date.today()
    changed = False
    for record in records:
        due_date = record.get("due_date")
        if (
            record.get("status") == "borrowed"
            and due_date
            and date.fromisoformat(due_date) < today
            and not record.get("overdue_notified", False)
        ):
            add_notification(f"Overdue reminder: {record.get('item', 'item')} (record {record.get('id')}).")
            record["overdue_notified"] = True
            changed = True
    if changed:
        _write_json_list(BORROW_FILE, records)


def search_records(keyword, key):
    keyword = keyword.strip().casefold()
    if not keyword:
        raise ValueError("Enter a keyword to search.")

    matches = []
    if DATA_FILE.exists():
        encrypted_record = json.loads(DATA_FILE.read_text(encoding="utf-8"))
        note = decrypt_note(encrypted_record, key)
        if keyword in note.casefold():
            matches.append("The encrypted study note matches your search.")

    for record in _read_json_list(BORROW_FILE):
        searchable_text = " ".join(str(value) for value in record.values()).casefold()
        if keyword in searchable_text:
            matches.append(
                f"Borrow record {record.get('id')}: {record.get('item')} "
                f"({record.get('status')}, student {record.get('student_id')})."
            )
    return matches


def display_borrow_records():
    records = _read_json_list(BORROW_FILE)
    if not records:
        print("No borrowing records yet.")
        return
    for record in records:
        print(
            f"{record.get('id')} | {record.get('item')} | {record.get('student_id')} | "
            f"{record.get('status')} | due {record.get('due_date')}"
        )


def main():
    key = load_or_create_key()
    check_overdue_reminders()

    actions = {
        "1": "Encrypt study note",
        "2": "Decrypt and verify note",
        "3": "Run ciphertext tamper test",
        "4": "Submit borrow request",
        "5": "Return borrowed item",
        "6": "Search notes and borrowing records",
        "7": "Show borrowing records",
        "8": "Show local notifications",
        "0": "Exit",
    }

    while True:
        print("\nSTUDY PULSE")
        for option, description in actions.items():
            print(f"{option}. {description}")
        choice = input("Choose an action: ").strip()

        try:
            if choice == "1":
                encrypt_note(input("Study note: "), key)
                add_notification("Study note encrypted and saved.")
                print("Note encrypted. Only its nonce and ciphertext are stored.")
            elif choice == "2":
                if not DATA_FILE.exists():
                    print("No encrypted study note was found.")
                else:
                    note = decrypt_note(json.loads(DATA_FILE.read_text(encoding="utf-8")), key)
                    print(f"Integrity verified. Recovered note:\n{note}")
                    add_notification("Study note decrypted and integrity verified.")
            elif choice == "3":
                tamper_test()
                add_notification("Tamper test altered the stored ciphertext.")
                print("One ciphertext bit was changed. Choose decrypt to see AES-GCM reject it.")
            elif choice == "4":
                record = request_borrow(input("Item name: "), input("Student ID: "))
                print(f"Borrow request saved. Record ID: {record['id']}; due: {record['due_date']}.")
            elif choice == "5":
                record = return_borrow(input("Borrow record ID: "))
                print(f"Returned: {record['item']}.")
            elif choice == "6":
                for match in search_records(input("Search keyword: "), key) or ["No matches found."]:
                    print(match)
            elif choice == "7":
                display_borrow_records()
            elif choice == "8":
                show_notifications()
            elif choice == "0":
                print("Goodbye.")
                break
            else:
                print("Choose one of the listed options.")
        except IntegrityFailure as error:
            print(error)
            add_notification("Integrity failure while verifying encrypted study data.")
        except (ValueError, FileNotFoundError, json.JSONDecodeError) as error:
            print(f"Could not complete that action: {error}")
        except OSError as error:
            print(f"A local file operation failed: {error}")


if __name__ == "__main__":
    main()