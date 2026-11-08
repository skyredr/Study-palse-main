from django.shortcuts import render
import json

import study_pulse_crypto as study

def index(request):
    msg = None
    is_error = False
    result_note = None
    tamper_info = None
    search_results = []
    search_performed = False
    search_query = ""
    active_view = "home-view"

    study.check_overdue_reminders()

    if request.method == "POST":
        action = request.POST.get("action")
        active_view = {
            "encrypt": "notes-view",
            "decrypt": "notes-view",
            "tamper_test": "tamper-view",
            "borrow": "borrowing-view",
            "return": "borrowing-view",
            "search": "notes-view",
        }.get(action, active_view)
        requested_view = request.POST.get("active_view")
        if requested_view in {"home-view", "notes-view", "tamper-view", "borrowing-view", "json-view"}:
            active_view = requested_view
        key = study.load_or_create_key()

        try:
            if action == "encrypt":
                study.encrypt_note(request.POST.get("study_note", ""), key)
                study.add_notification("Study note encrypted and saved.")
                msg = "Study note encrypted and saved using AES-256-GCM."
            elif action == "decrypt":
                if not study.DATA_FILE.exists():
                    raise FileNotFoundError("No encrypted study note was found.")
                record = json.loads(study.DATA_FILE.read_text(encoding="utf-8"))
                result_note = study.decrypt_note(record, key)
                study.add_notification("Study note decrypted and integrity verified.")
                msg = "Decryption and integrity verification succeeded."
            elif action == "tamper_test":
                study.tamper_test()
                study.add_notification("Tamper test altered the stored ciphertext.")
                tamper_info = "One bit of the stored ciphertext was changed. Decrypt it to verify AES-GCM rejects it."
                msg = "Tamper simulation applied."
            elif action == "borrow":
                record = study.request_borrow(
                    request.POST.get("item_name", ""),
                    request.POST.get("student_id", ""),
                )
                msg = f"Borrow request submitted. Record ID: {record['id']}."
            elif action == "return":
                record = study.return_borrow(request.POST.get("record_id", ""))
                msg = f"Returned {record['item']}."
            elif action == "search":
                search_query = request.POST.get("keyword", "")
                search_performed = True
                search_results = study.search_records(search_query, key)
        except study.IntegrityFailure as error:
            msg = str(error)
            is_error = True
            if active_view == "tamper-view":
                tamper_info = msg
            study.add_notification("Integrity failure while verifying encrypted study data.")
        except (ValueError, OSError, json.JSONDecodeError) as error:
            msg = str(error)
            is_error = True

    json_display = ""
    note_exists = study.DATA_FILE.exists()
    if note_exists:
        json_display = study.DATA_FILE.read_text(encoding="utf-8")

    integrity_status = "No note saved"
    if note_exists:
        try:
            study.decrypt_note(json.loads(json_display), study.load_or_create_key())
            integrity_status = "Verified"
        except study.IntegrityFailure:
            integrity_status = "Integrity failure"
        except (ValueError, json.JSONDecodeError):
            integrity_status = "Invalid encrypted data"

    borrow_records = study._read_json_list(study.BORROW_FILE)
    notifications = study._read_json_list(study.NOTIFICATIONS_FILE)[-5:][::-1]
    active_borrow_count = sum(record.get("status") == "borrowed" for record in borrow_records)

    context = {
        "msg": msg,
        "is_error": is_error,
        "result_note": result_note,
        "tamper_info": tamper_info,
        "json_display": json_display,
        "active_view": active_view,
        "search_query": search_query,
        "search_performed": search_performed,
        "search_results": search_results,
        "borrow_records": borrow_records,
        "active_borrow_count": active_borrow_count,
        "notifications": notifications,
        "note_exists": note_exists,
        "integrity_status": integrity_status,
    }
    return render(request, "core/index.html", context)