from app.security import hash_password, verify_password


def test_hash_is_not_plaintext_and_verifies():
    h = hash_password("correct-horse-battery")
    assert h != "correct-horse-battery"
    assert h.startswith("$argon2")
    assert verify_password("correct-horse-battery", h)
    assert not verify_password("wrong-password-123", h)


def test_same_password_gets_different_hashes():
    assert hash_password("same-password-123") != hash_password("same-password-123")


def test_verify_handles_garbage_hash():
    assert not verify_password("anything", "not-a-real-hash")
