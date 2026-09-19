"""Traer desde la nube (gpull.CloudImport): los dos modos, sin red.

El origen "remoto" se simula con un adaptador de solo lectura sobre una
carpeta .vault real en disco (header/index/blobs), que es exactamente la
interfaz que consume Vault.open_remote y ChunkReader."""

import shutil
from pathlib import Path

import pytest

from vaultjam.gpull import CloudImport
from vaultjam.vault import Vault

# Argon2 mínimo: las pruebas no evalúan la fortaleza del KDF, solo la lógica.
FAST_KDF = {"m_kib": 8, "t": 1, "p": 1}


class DirRemote:
    """Almacén remoto de solo lectura sobre una carpeta .vault en disco:
    la misma interfaz (read_header/read_index/read) que usa DriveStore."""

    read_only = True

    def __init__(self, root: Path):
        self.root = Path(root)

    def read_header(self) -> bytes:
        return (self.root / "header.json").read_bytes()

    def read_index(self) -> bytes:
        return (self.root / "index.enc").read_bytes()

    def read(self, blob_id: str) -> bytes:
        return (self.root / "blobs" / blob_id[:2] / f"{blob_id}.blob").read_bytes()


def _make_vault(path: Path, pw: str) -> Vault:
    return Vault.create(path, pw, params=FAST_KDF)


def test_import_mode_distinct_vault(tmp_path):
    # Origen: bóveda distinta con un archivo.
    src_dir = tmp_path / "origen.vault"
    src = _make_vault(src_dir, "clave-origen")
    payload = b"contenido de prueba \x00\x01\x02" * 5000  # ~ varios chunks
    e0 = src.import_bytes("foto.jpg", payload, "image", b"thumbjpeg", folder="viaje")
    src.set_favorite(e0.id, True)
    src.lock()

    # Destino: bóveda local vacía con OTRA contraseña (⇒ otra clave maestra).
    dst = _make_vault(tmp_path / "destino.vault", "clave-destino")

    src_ro = Vault.open_remote(DirRemote(src_dir), "clave-origen")
    imp = CloudImport(src_ro, dst)
    assert imp.same_vault is False and imp.mode == "importar"

    res = imp.run([e0.id])
    assert res["importados"] == 1 and res["omitidos"] == 0

    # El contenido descifrado en destino coincide con el original.
    got = dst.entries(folder="viaje")
    assert len(got) == 1
    ne = got[0]
    assert ne.name == "foto.jpg" and ne.favorite is True   # metadata copiada
    assert ne.id != e0.id                                   # id/blobs nuevos
    r = dst.open_reader(ne.id)
    assert r.read(-1) == payload

    # Reintentar no duplica (dedup por nombre/tamaño/fecha/carpeta).
    res2 = imp.run([e0.id])
    assert res2["importados"] == 0 and res2["omitidos"] == 1
    assert len(dst.entries(folder="viaje")) == 1


def test_mirror_mode_same_vault_restores_missing(tmp_path):
    # Bóveda V con un archivo.
    v_dir = tmp_path / "V.vault"
    v = _make_vault(v_dir, "misma-clave")
    payload = b"pixeles" * 40000
    e0 = v.import_bytes("clip.mp4", payload, "video", b"thumb", folder="")
    eid, chunk_ids, thumb_id = e0.id, list(e0.chunks), e0.thumb

    # "Espejo" en la nube = copia íntegra de V.
    mirror_dir = tmp_path / "V-mirror.vault"
    shutil.copytree(v_dir, mirror_dir)

    # Simular que la copia LOCAL perdió esa entrada y sus blobs.
    v._entries.pop(eid)
    v._save_index()
    for bid in chunk_ids + [thumb_id]:
        v.store.delete(bid)
    assert v.entries() == []

    # Abrir el espejo (misma contraseña ⇒ misma clave maestra) y traer.
    src_ro = Vault.open_remote(DirRemote(mirror_dir), "misma-clave")
    imp = CloudImport(src_ro, v)
    assert imp.same_vault is True and imp.mode == "espejo"

    res = imp.run([eid])
    assert res["añadidos"] == 1 and res["importados"] == 0

    # Entrada reinjertada con su MISMO id y blobs; se lee el original.
    assert eid in {e.id for e in v.entries()}
    assert v.get(eid).chunks == chunk_ids            # ids de blob conservados
    assert v.open_reader(eid).read(-1) == payload

    # Reintentar: ya está todo ⇒ omitido.
    assert imp.run([eid])["omitidos"] == 1


def test_same_master_key_detection(tmp_path):
    a = _make_vault(tmp_path / "a.vault", "p1")
    shutil.copytree(tmp_path / "a.vault", tmp_path / "a-copy.vault")
    a_copy = Vault.open_remote(DirRemote(tmp_path / "a-copy.vault"), "p1")
    b = _make_vault(tmp_path / "b.vault", "p2")
    assert a.same_master_key(a_copy) is True     # misma bóveda
    assert a.same_master_key(b) is False         # bóvedas distintas
