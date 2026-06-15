import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from management.api import auth


class TestPasswordHashing:
    def test_hash_then_verify(self):
        h = auth.hash_password("s3cret!")
        assert h.startswith("pbkdf2_sha256$")
        assert auth.verify_password("s3cret!", h)
        assert not auth.verify_password("wrong", h)

    def test_distinct_salts(self):
        assert auth.hash_password("x") != auth.hash_password("x")  # random salt

    def test_verify_garbage_stored(self):
        assert not auth.verify_password("x", "")
        assert not auth.verify_password("x", "notahash")


class TestSessionToken:
    def test_valid_token_round_trip(self):
        ph, sk = auth.hash_password("pw"), auth.new_secret()
        tok = auth.session_token(ph, sk)
        assert auth.token_valid(tok, ph, sk)

    def test_wrong_token_rejected(self):
        ph, sk = auth.hash_password("pw"), auth.new_secret()
        assert not auth.token_valid("deadbeef", ph, sk)
        assert not auth.token_valid(None, ph, sk)

    def test_password_change_invalidates(self):
        sk = auth.new_secret()
        ph1, ph2 = auth.hash_password("old"), auth.hash_password("new")
        tok = auth.session_token(ph1, sk)
        assert not auth.token_valid(tok, ph2, sk)  # old cookie no longer valid

    def test_missing_secret_or_hash(self):
        assert not auth.token_valid("x", "", "")
