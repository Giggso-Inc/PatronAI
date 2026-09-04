from __future__ import annotations

from pathlib import Path

from apikey_scanner.catalog.validators import hex_even_length, luhn
from apikey_scanner.secret_salt import fingerprint, hash_author, load_or_create_salt


def test_luhn_valid_card_like_number():
    assert luhn("4532015112830366") is True  # a well-known Luhn-valid test number


def test_luhn_invalid_number():
    assert luhn("4532015112830367") is False


def test_luhn_rejects_non_digit_candidate():
    assert luhn("not-a-number") is False


def test_luhn_rejects_too_short():
    assert luhn("4") is False


def test_hex_even_length_valid():
    assert hex_even_length("deadbeef") is True


def test_hex_even_length_odd_rejected():
    assert hex_even_length("abc") is False


def test_hex_even_length_with_0x_prefix():
    assert hex_even_length("0xdeadbeef") is True


def test_hex_even_length_rejects_non_hex_chars():
    assert hex_even_length("zzzzzzzz") is False


def test_salt_created_once_and_reused(tmp_path: Path):
    salt_path = tmp_path / ".apikey-scanner" / "salt"
    salt_a = load_or_create_salt(salt_path)
    salt_b = load_or_create_salt(salt_path)
    assert salt_a == salt_b
    assert len(salt_a) == 32


def test_fingerprint_is_stable_for_same_salt_and_value():
    salt = b"a" * 32
    assert fingerprint(salt, "same-secret") == fingerprint(salt, "same-secret")


def test_fingerprint_differs_across_salts():
    assert fingerprint(b"a" * 32, "secret") != fingerprint(b"b" * 32, "secret")


def test_fingerprint_never_contains_the_secret():
    salt = b"a" * 32
    secret = "AKIAQ7ZP4XKM9LWD2FTR"
    fp = fingerprint(salt, secret)
    assert secret not in fp


def test_hash_author_is_stable_and_hides_identity():
    salt = b"a" * 32
    hashed = hash_author(salt, "person@example.com")
    assert hashed == hash_author(salt, "person@example.com")
    assert "person@example.com" not in hashed
