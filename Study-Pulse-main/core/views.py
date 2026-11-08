import json
import os
from pathlib import Path
from django.shortcuts import render
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

KEY_FILE = Path("study_pulse.key")
DATA_FILE = Path("encrypted_study_note.json")

def get_or_create_key():
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()
    key = AESGCM.generate_key(bit_length=256)
    KEY_FILE.write_bytes(key)
    return key

def index(request):
    msg = None
    is_error = False
    result_note = None
    tamper_info = None

    key = get_or_create_key()

    if request.method == "POST":
        action = request.POST.get("action")

        # 1. ENCRYPT ACTION
        if action == "encrypt":
            note = request.POST.get("study_note", "").strip()
            if note:
                aesgcm = AESGCM(key)
                nonce = os.urandom(12)  # 96-bit nonce
                ciphertext = aesgcm.encrypt(nonce, note.encode("utf-8"), None)
                
                record = {
                    "algorithm": "AES-256-GCM",
                    "nonce": nonce.hex(),
                    "ciphertext": ciphertext.hex()
                }
                DATA_FILE.write_text(json.dumps(record, indent=2), encoding="utf-8")
                msg = "Successfully encrypted and saved note using AES-256-GCM!"
            else:
                msg = "Please enter a study note to encrypt."
                is_error = True

        # 2. DECRYPT ACTION
        elif action == "decrypt":
            if DATA_FILE.exists():
                try:
                    record = json.loads(DATA_FILE.read_text(encoding="utf-8"))
                    aesgcm = AESGCM(key)
                    nonce = bytes.fromhex(record["nonce"])
                    ciphertext = bytes.fromhex(record["ciphertext"])
                    
                    recovered = aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")
                    result_note = recovered
                    msg = "Decryption & authentication verification successful!"
                except InvalidTag:
                    msg = "INTEGRITY FAILURE: Data has been tampered with or key is invalid!"
                    is_error = True
                except Exception as e:
                    msg = f"Decryption error: {str(e)}"
                    is_error = True
            else:
                msg = "No encrypted note file found."
                is_error = True

        # 3. TAMPER DEMO ACTION
        elif action == "tamper_test":
            if DATA_FILE.exists():
                record = json.loads(DATA_FILE.read_text(encoding="utf-8"))
                original_ct = record["ciphertext"]
                
                # Corrupt the last byte of ciphertext to simulate tampering
                raw_ct = bytearray(bytes.fromhex(original_ct))
                raw_ct[-1] ^= 0xFF
                record["ciphertext"] = raw_ct.hex()
                
                DATA_FILE.write_text(json.dumps(record, indent=2), encoding="utf-8")
                tamper_info = "⚠️ 1 byte of stored ciphertext was deliberately modified! Now try clicking 'Decrypt Note' to test if GCM detects the tampering."
                msg = "Tamper simulation applied to JSON file."
                is_error = True

    # Load JSON for display in UI
    json_display = ""
    if DATA_FILE.exists():
        json_display = DATA_FILE.read_text(encoding="utf-8")

    context = {
        "msg": msg,
        "is_error": is_error,
        "result_note": result_note,
        "tamper_info": tamper_info,
        "json_display": json_display,
    }
    return render(request, "core/index.html", context)