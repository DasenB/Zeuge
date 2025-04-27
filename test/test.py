import requests
import json
import time

BASE_URL = "http://127.0.0.1:3000"  # Change if your server is somewhere else

def create_proof(hash_value, algorithm, comment=None, public_key=None, signature=None):
    payload = {
        "hash": hash_value,
        "algorithm": algorithm,
        "comment": comment,
        "public_key": public_key,
        "signature": signature
    }
    # Remove None fields
    payload = {k: v for k, v in payload.items() if v is not None}

    response = requests.post(f"{BASE_URL}/proofs", json=payload)
    return response

def get_proof_by_hash(hash_value):
    response = requests.get(f"{BASE_URL}/proofs/{hash_value}")
    return response

def get_proofs_by_time(start, end, page=0, page_size=10):
    params = {
        "start": start,
        "end": end,
        "page": page,
        "page_size": page_size
    }
    response = requests.get(f"{BASE_URL}/proofs_by_time", params=params)
    return response

def main():
    print("✅ Starting API Tests")

    # --- Test 1: Valid Proof Creation ---
    print("\n▶ Test 1: Valid proof without signature")
    valid_hash = "abc123def4567890abc123def4567890abc123def4567890abc123def4567890"
    response = create_proof(valid_hash, "SHA2_256", comment="This is valid")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")

    assert response.status_code in (200, 201), "Failed to create valid proof"

    # --- Test 2: Missing Algorithm ---
    print("\n▶ Test 2: Invalid proof (missing algorithm)")
    response = create_proof("deadbeef", None, comment="Missing algorithm")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")
    assert response.status_code != 200, "Invalid proof should not be accepted"

    # --- Test 3: Only public_key without signature ---
    print("\n▶ Test 3: Invalid proof (only public key, no signature)")
    response = create_proof("deadbeef1234", "SHA2_256", comment="Only pubkey", public_key="fake_public_key")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")
    assert response.status_code != 200, "Proof with only public key should be rejected"

    # --- Test 4: Only signature without public_key ---
    print("\n▶ Test 4: Invalid proof (only signature, no public key)")
    response = create_proof("beefdead1234", "SHA2_256", comment="Only signature", signature="fake_signature")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")
    assert response.status_code != 200, "Proof with only signature should be rejected"

    # --- Test 5: Fetch by hash ---
    print("\n▶ Test 5: Fetch created proof by hash")
    response = get_proof_by_hash(valid_hash)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")
    assert response.status_code == 200, "Failed to fetch proof by hash"

    # --- Test 6: Fetch by time (current window) ---
    print("\n▶ Test 6: Fetch proofs by time")
    now = int(time.time())
    response = get_proofs_by_time(start=now - 600, end=now + 600, page=1, page_size=5)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")
    assert response.status_code == 200, "Failed to fetch proofs by time"

    # --- Test 7: Valid Proof Creation ---
    print("\n▶ Test 7: Test rejection of invalid hashes")
    valid_hash = "abc123def4567890"
    response = create_proof(valid_hash, "SHA2_256", comment="This is valid")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")

    assert response.status_code not in (200, 201), "Created invalid proof."


    print("\n🎉 All tests completed successfully!")

if __name__ == "__main__":
    main()
