"""Pruebas del núcleo criptográfico.

Los parámetros de Argon2 en tests son mínimos (m=8 MiB) solo para velocidad;
la app usa 256 MiB. La corrección del ensamblaje no depende del coste.
"""

import pytest

from vaultjam import crypto_core as cc

FAST = {"m_kib": 8192, "t": 1, "p": 1}
SALT = b"\x01" * cc.SALT_LEN


def test_kdf_deterministic_and_salt_sensitive():
    k1 = cc.derive_kek(b"password", SALT, **FAST)
    k2 = cc.derive_kek(b"password", SALT, **FAST)
    k3 = cc.derive_kek(b"password", b"\x02" * cc.SALT_LEN, **FAST)
    k4 = cc.derive_kek(b"passwore", SALT, **FAST)
    assert bytes(k1) == bytes(k2)
    assert bytes(k1) != bytes(k3)  # salt distinto -> clave distinta
    assert bytes(k1) != bytes(k4)  # contraseña distinta -> clave distinta
    assert len(k1) == cc.KEY_LEN


def test_wrap_unwrap_roundtrip():
    kek = cc.derive_kek(b"pw", SALT, **FAST)
    mk = bytearray(cc.random_bytes(cc.KEY_LEN))
    aad = cc.kdf_aad(FAST["m_kib"], FAST["t"], FAST["p"], SALT)
    wrapped = cc.wrap_master_key(kek, mk, aad)
    assert bytes(cc.unwrap_master_key(kek, wrapped, aad)) == bytes(mk)


def test_unwrap_wrong_password_fails():
    kek = cc.derive_kek(b"pw", SALT, **FAST)
    bad = cc.derive_kek(b"otra", SALT, **FAST)
    aad = cc.kdf_aad(FAST["m_kib"], FAST["t"], FAST["p"], SALT)
    wrapped = cc.wrap_master_key(kek, bytearray(32), aad)
    with pytest.raises(cc.VaultCryptoError):
        cc.unwrap_master_key(bad, wrapped, aad)


def test_unwrap_tampered_kdf_params_fails():
    """Debilitar los parámetros Argon2 del header rompe el AAD del envoltorio."""
    kek = cc.derive_kek(b"pw", SALT, **FAST)
    aad = cc.kdf_aad(FAST["m_kib"], FAST["t"], FAST["p"], SALT)
    wrapped = cc.wrap_master_key(kek, bytearray(32), aad)
    weakened = cc.kdf_aad(8, 1, 1, SALT)
    with pytest.raises(cc.VaultCryptoError):
        cc.unwrap_master_key(kek, wrapped, weakened)


def test_seal_open_roundtrip_and_tamper():
    keys = cc.derive_subkeys(cc.random_bytes(32))
    fid = cc.random_bytes(16)
    aad = cc.chunk_aad(fid, 0, 3)
    pt = cc.random_bytes(1000)
    blob = cc.seal(keys.content, pt, aad)
    assert cc.open_sealed(keys.content, blob, aad) == pt

    # Cualquier bit alterado (nonce, ct o tag) debe fallar.
    for pos in (0, cc.NONCE_LEN + 10, len(blob) - 1):
        bad = bytearray(blob)
        bad[pos] ^= 0x01
        with pytest.raises(cc.VaultCryptoError):
            cc.open_sealed(keys.content, bytes(bad), aad)


def test_aad_binds_position_file_and_total():
    """Un chunk no puede moverse de posición, de archivo ni de un archivo truncado."""
    keys = cc.derive_subkeys(cc.random_bytes(32))
    fid = cc.random_bytes(16)
    blob = cc.seal(keys.content, b"data", cc.chunk_aad(fid, 0, 2))
    for bad_aad in (
        cc.chunk_aad(fid, 1, 2),                  # otra posición
        cc.chunk_aad(cc.random_bytes(16), 0, 2),  # otro archivo
        cc.chunk_aad(fid, 0, 1),                  # total truncado
    ):
        with pytest.raises(cc.VaultCryptoError):
            cc.open_sealed(keys.content, blob, bad_aad)


def test_domain_separation():
    """Un mensaje sellado como contenido no se abre con la clave de índice."""
    keys = cc.derive_subkeys(cc.random_bytes(32))
    blob = cc.seal(keys.content, b"data", cc.index_aad())
    with pytest.raises(cc.VaultCryptoError):
        cc.open_sealed(keys.index, blob, cc.index_aad())


def test_nonces_never_repeat_across_seals():
    keys = cc.derive_subkeys(cc.random_bytes(32))
    nonces = {cc.seal(keys.content, b"x", b"a")[: cc.NONCE_LEN] for _ in range(200)}
    assert len(nonces) == 200


def test_zeroize():
    buf = bytearray(b"secreto-secreto")
    cc.zeroize(buf)
    assert bytes(buf) == b"\x00" * 15
