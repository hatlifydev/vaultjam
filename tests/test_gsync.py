"""Pruebas del sincronizador local -> Drive contra un Drive EN MEMORIA que
implementa la misma interfaz que DriveOps. Cubre: espejo completo, segunda
pasada sin re-subidas, corrección de blobs corruptos, cancelación segura
(índice intacto) y que el espejo resultante es una bóveda remota usable."""

import threading
from pathlib import Path

import pytest
from PIL import Image

from vaultjam import crypto_core as cc
from vaultjam.gsync import EXPECTED_BLOB_SIZE, DriveSyncer
from vaultjam.thumbs import make_thumbnail
from vaultjam.vault import Vault

FAST = {"m_kib": 8192, "t": 1, "p": 1}
PW = "clave-de-sync"


class MemOps:
    """Drive en memoria con la interfaz de DriveOps."""

    def __init__(self):
        self._n = 0
        self.nodes: dict[str, dict] = {}   # id -> {name,parent,folder,data}
        self._mutex = threading.Lock()     # la subida paralela escribe aquí

    def _new(self, name, parent, folder, data=b""):
        with self._mutex:
            self._n += 1
            nid = f"n{self._n}"
            self.nodes[nid] = {"name": name, "parent": parent,
                               "folder": folder, "data": data}
            return nid

    def find_folders(self, name):
        return [i for i, d in self.nodes.items()
                if d["folder"] and d["name"] == name]

    def folder_exists(self, folder_id):
        d = self.nodes.get(folder_id)
        return bool(d and d["folder"])

    def create_folder(self, parent_id, name):
        return self._new(name, parent_id, True)

    def list_children(self, folder_id):
        return {d["name"]: {"id": i, "size": (None if d["folder"] else len(d["data"]))}
                for i, d in self.nodes.items() if d["parent"] == folder_id}

    def list_children_many(self, parent_ids):
        parents = set(parent_ids)
        return {d["name"]: {"id": i, "size": (None if d["folder"] else len(d["data"]))}
                for i, d in self.nodes.items() if d["parent"] in parents}

    def upload(self, parent_id, name, path, existing_id=None):
        data = Path(path).read_bytes()
        if existing_id:
            with self._mutex:
                self.nodes[existing_id]["data"] = data
            return existing_id
        return self._new(name, parent_id, False, data)


class MemRemoteStore:
    """Lee el espejo en memoria con la interfaz de DriveStore: demuestra
    que lo sincronizado es una bóveda remota abrible tal cual."""

    def __init__(self, ops: MemOps, folder_id: str):
        self.ops = ops
        self.fid = folder_id

    def _child(self, folder_id, name):
        return self.ops.list_children(folder_id)[name]["id"]

    def read_header(self):
        return self.ops.nodes[self._child(self.fid, "header.json")]["data"]

    def read_index(self):
        return self.ops.nodes[self._child(self.fid, "index.enc")]["data"]

    def read(self, blob_id):
        blobs = self._child(self.fid, "blobs")
        sub = self._child(blobs, blob_id[:2])
        return self.ops.nodes[self._child(sub, f"{blob_id}.blob")]["data"]


@pytest.fixture()
def synced(tmp_path):
    vault = Vault.create(tmp_path / "v.vault", PW, FAST)
    photo = tmp_path / "f.png"
    Image.new("RGB", (300, 200), (10, 90, 40)).save(photo)
    vault.import_file(photo, "image", make_thumbnail(photo, "image"))
    big = tmp_path / "b.mp4"
    big.write_bytes(b"\x07" * int(2.5 * cc.CHUNK_SIZE))
    vault.import_file(big, "video", None)
    ops = MemOps()
    syncer = DriveSyncer(ops, vault.root, vault.all_blob_ids(),
                         folder_name="v.vault")
    return vault, ops, syncer, big.read_bytes()


def test_sync_full_mirror_and_second_pass(synced):
    vault, ops, syncer, original = synced
    n = len(vault.all_blob_ids())

    s1 = syncer.sync()
    assert not s1["cancelado"]
    assert s1["subidos"] == n and s1["ya_presentes"] == 0
    assert s1["huerfanos"] == 0
    assert s1["ok_blobs"] == set(vault.all_blob_ids())   # para los marcos

    # segunda pasada: nada que subir (reanudable e idempotente)
    s2 = DriveSyncer(ops, vault.root, vault.all_blob_ids(),
                     folder_name="v.vault").sync()
    assert s2["subidos"] == 0 and s2["ya_presentes"] == n
    assert s2["folder_id"] == s1["folder_id"]

    # el espejo es una bóveda remota usable, bit a bit
    rv = Vault.open_remote(MemRemoteStore(ops, s1["folder_id"]), PW)
    ev = next(e for e in rv.entries() if e.mime == "video")
    assert rv.open_reader(ev.id).read(-1) == original


def test_sync_repairs_wrong_size_blob(synced):
    vault, ops, syncer, _ = synced
    s1 = syncer.sync()
    # corromper un blob remoto (tamaño incorrecto = subida a medias)
    victim = next(i for i, d in ops.nodes.items()
                  if d["name"].endswith(".blob"))
    ops.nodes[victim]["data"] = b"x" * 100
    s2 = DriveSyncer(ops, vault.root, vault.all_blob_ids(),
                     folder_name="v.vault").sync()
    assert s2["subidos"] == 1 and s2["corregidos"] == 1
    assert len(ops.nodes[victim]["data"]) == EXPECTED_BLOB_SIZE


def test_sync_cancel_leaves_index_untouched(synced):
    vault, ops, syncer, _ = synced
    calls = {"n": 0}

    def cancel_after_two():
        calls["n"] += 1
        return calls["n"] > 2

    s = syncer.sync(cancelled=cancel_after_two)
    assert s["cancelado"] and s["subidos"] == 2 and s["pendientes"] > 0
    # el punto de commit no se alcanzó: sin índice ni header en el espejo
    names = {d["name"] for d in ops.nodes.values()}
    assert "index.enc" not in names and "header.json" not in names
    # reanudar termina el trabajo
    s2 = DriveSyncer(ops, vault.root, vault.all_blob_ids(),
                     folder_name="v.vault").sync()
    assert not s2["cancelado"]
    assert s2["subidos"] == s["pendientes"]


def test_sync_parallel_full_mirror(synced):
    """El camino paralelo (workers>1 + fábrica de ops) produce exactamente
    el mismo espejo que el secuencial, usable como bóveda remota."""
    vault, ops, _seq, original = synced
    n = len(vault.all_blob_ids())
    syncer = DriveSyncer(ops, vault.root, vault.all_blob_ids(),
                         folder_name="v.vault",
                         ops_factory=lambda: ops, workers=4)
    s = syncer.sync()
    assert not s["cancelado"] and s["subidos"] == n
    assert s["ok_blobs"] == set(vault.all_blob_ids())
    rv = Vault.open_remote(MemRemoteStore(ops, s["folder_id"]), PW)
    ev = next(e for e in rv.entries() if e.mime == "video")
    assert rv.open_reader(ev.id).read(-1) == original
    # segunda pasada paralela: idempotente
    s2 = DriveSyncer(ops, vault.root, vault.all_blob_ids(),
                     folder_name="v.vault",
                     ops_factory=lambda: ops, workers=4).sync()
    assert s2["subidos"] == 0 and s2["ya_presentes"] == n


def test_sync_parallel_cancel_keeps_index_untouched(synced):
    vault, ops, _seq, _ = synced
    calls = {"n": 0}

    def cancel_soon():
        calls["n"] += 1
        return calls["n"] > 1

    s = DriveSyncer(ops, vault.root, vault.all_blob_ids(),
                    folder_name="v.vault",
                    ops_factory=lambda: ops, workers=4).sync(
        cancelled=cancel_soon)
    assert s["cancelado"]
    assert s["subidos"] + s["pendientes"] == s["total"]
    names = {d["name"] for d in ops.nodes.values()}
    assert "index.enc" not in names and "header.json" not in names
    # reanudar en paralelo completa el espejo
    s2 = DriveSyncer(ops, vault.root, vault.all_blob_ids(),
                     folder_name="v.vault",
                     ops_factory=lambda: ops, workers=4).sync()
    assert not s2["cancelado"]
    assert s2["subidos"] == s["pendientes"]


def test_mirrored_blobs_verify_only(synced):
    vault, ops, syncer, _ = synced
    # sin espejo aún: verificar NO debe crear nada
    with pytest.raises(RuntimeError, match="No existe"):
        DriveSyncer(ops, vault.root, [], folder_name="v.vault").mirrored_blobs()
    assert ops.find_folders("v.vault") == []
    # tras sincronizar: devuelve el inventario correcto
    s = syncer.sync()
    fid, ok = DriveSyncer(ops, vault.root, [],
                          folder_name="v.vault").mirrored_blobs()
    assert fid == s["folder_id"] and ok == set(vault.all_blob_ids())
    # un blob a medias (tamaño malo) queda fuera del conjunto «ok»
    victim_blob = vault.all_blob_ids()[0]
    victim = next(i for i, d in ops.nodes.items()
                  if d["name"] == f"{victim_blob}.blob")
    ops.nodes[victim]["data"] = b"x" * 10
    _, ok2 = DriveSyncer(ops, vault.root, [],
                         folder_name="v.vault").mirrored_blobs()
    assert victim_blob not in ok2 and len(ok2) == len(ok) - 1


def test_sync_ambiguous_folder_refuses(synced):
    vault, ops, syncer, _ = synced
    ops.create_folder(None, "v.vault")
    ops.create_folder(None, "v.vault")
    with pytest.raises(RuntimeError, match="carpetas"):
        syncer.sync()
