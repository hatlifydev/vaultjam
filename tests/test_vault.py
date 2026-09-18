"""Pruebas de integración del contenedor: crear/abrir, importar/exportar,
propiedades anti-fuga de metadatos y resistencia a manipulación en disco."""

import io
import json
import os
from pathlib import Path

import pytest
from PIL import Image

from vaultjam import crypto_core as cc
from vaultjam.storage import FIXED_TS
from vaultjam.thumbs import make_thumbnail
from vaultjam.vault import Vault, VaultError

FAST = {"m_kib": 8192, "t": 1, "p": 1}
PW = "contraseña-de-prueba"


@pytest.fixture()
def vault(tmp_path):
    return Vault.create(tmp_path / "v.vault", PW, FAST)


def make_photo(tmp_path, name="foto.png", size=(640, 480)) -> Path:
    img = Image.new("RGB", size)
    px = img.load()
    for x in range(size[0]):
        for y in range(0, size[1], 7):
            px[x, y] = (x % 256, y % 256, (x * y) % 256)
    p = tmp_path / name
    img.save(p)
    return p


def make_big_file(tmp_path, name="video.mp4", nbytes=int(2.5 * cc.CHUNK_SIZE)) -> Path:
    p = tmp_path / name
    p.write_bytes(os.urandom(nbytes))
    return p


def _import(vault, path, mime="image"):
    return vault.import_file(path, mime, make_thumbnail(path, mime))


def test_create_reopen_and_wrong_password(tmp_path, vault):
    photo = make_photo(tmp_path)
    e = _import(vault, photo)
    vault.lock()

    v2 = Vault.open(tmp_path / "v.vault", PW)
    assert [x.name for x in v2.entries()] == ["foto.png"]
    assert v2.get(e.id).size == photo.stat().st_size

    with pytest.raises(cc.VaultCryptoError):
        Vault.open(tmp_path / "v.vault", "incorrecta")


def test_roundtrip_export_identical(tmp_path, vault):
    src = make_big_file(tmp_path)  # multi-chunk, con padding en el último
    e = vault.import_file(src, "video", None)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    out = vault.export_file(e.id, out_dir)
    assert out.read_bytes() == src.read_bytes()


def test_reader_random_access(tmp_path, vault):
    src = make_big_file(tmp_path, nbytes=3 * cc.CHUNK_SIZE + 12345)
    original = src.read_bytes()
    e = vault.import_file(src, "video", None)
    r = vault.open_reader(e.id)
    assert r.size == len(original)
    # saltos aleatorios como los que hace un demuxer de video
    for start, ln in [(0, 100), (cc.CHUNK_SIZE - 5, 20), (2 * cc.CHUNK_SIZE + 7, 50000),
                      (len(original) - 33, 100), (len(original) - 1, 1)]:
        r.seek(start)
        assert r.read(ln) == original[start : start + ln]
    r.seek(-10, 2)
    assert r.read() == original[-10:]


def test_thumbnail_encrypted_and_recoverable(tmp_path, vault):
    e = _import(vault, make_photo(tmp_path))
    data = vault.read_thumb(e.id)
    assert data is not None and data[:2] == b"\xff\xd8"  # es un JPEG
    # y en disco NO existe ningún JPEG en claro
    for f in (tmp_path / "v.vault").rglob("*"):
        if f.is_file():
            assert not f.read_bytes().startswith(b"\xff\xd8")


def test_all_blobs_identical_size_and_normalized_timestamps(tmp_path, vault):
    _import(vault, make_photo(tmp_path, "a.png"))
    vault.import_file(make_big_file(tmp_path, "b.mp4"), "video", None)
    blobs = list((tmp_path / "v.vault" / "blobs").rglob("*.blob"))
    assert len(blobs) >= 5  # 1 chunk foto + thumb + 3 chunks video
    sizes = {b.stat().st_size for b in blobs}
    # TODOS los blobs miden exactamente chunk + nonce + tag
    assert sizes == {cc.CHUNK_SIZE + cc.NONCE_LEN + cc.TAG_LEN}
    for b in blobs:
        assert int(b.stat().st_mtime) == FIXED_TS


def test_index_padded_to_power_of_two(tmp_path, vault):
    for i in range(5):
        _import(vault, make_photo(tmp_path, f"f{i}.png"))
    n = (tmp_path / "v.vault" / "index.enc").stat().st_size - cc.NONCE_LEN - cc.TAG_LEN
    assert n >= 4096 and (n & (n - 1)) == 0  # potencia de dos


def test_no_plaintext_metadata_on_disk(tmp_path, vault):
    """Ni nombres, ni contenido, ni estructura aparecen en claro en el disco."""
    secret_name = "mi-nombre-secretisimo.png"
    _import(vault, make_photo(tmp_path, secret_name))
    for f in (tmp_path / "v.vault").rglob("*"):
        if f.is_file():
            assert secret_name.encode() not in f.read_bytes()
    header = json.loads((tmp_path / "v.vault" / "header.json").read_text())
    assert set(header) == {"magic", "version", "kdf", "mk_wrapped"}


def test_tampered_blob_detected(tmp_path, vault):
    src = make_big_file(tmp_path)
    e = vault.import_file(src, "video", None)
    blob_path = vault.store.path_for(e.chunks[1])
    raw = bytearray(blob_path.read_bytes())
    raw[len(raw) // 2] ^= 0x01  # voltear un bit del ciphertext
    blob_path.write_bytes(bytes(raw))
    r = vault.open_reader(e.id)
    r.seek(cc.CHUNK_SIZE)  # caer en el chunk manipulado
    with pytest.raises(cc.VaultCryptoError):
        r.read(10)


def test_swapped_chunks_detected(tmp_path, vault):
    """Intercambiar físicamente dos blobs del mismo archivo debe detectarse:
    el AAD ata cada chunk a su posición."""
    src = make_big_file(tmp_path)
    e = vault.import_file(src, "video", None)
    p0, p1 = vault.store.path_for(e.chunks[0]), vault.store.path_for(e.chunks[1])
    d0, d1 = p0.read_bytes(), p1.read_bytes()
    p0.write_bytes(d1)
    p1.write_bytes(d0)
    r = vault.open_reader(e.id)
    with pytest.raises(cc.VaultCryptoError):
        r.read(10)


def test_delete_removes_blobs(tmp_path, vault):
    e = _import(vault, make_photo(tmp_path))
    blob_dir = tmp_path / "v.vault" / "blobs"
    assert list(blob_dir.rglob("*.blob"))
    vault.delete_file(e.id)
    assert not list(blob_dir.rglob("*.blob"))
    assert vault.entries() == []


def test_change_password(tmp_path, vault):
    e = _import(vault, make_photo(tmp_path))
    vault.change_password(PW, "nueva-contraseña", FAST)
    vault.lock()
    with pytest.raises(cc.VaultCryptoError):
        Vault.open(tmp_path / "v.vault", PW)
    v2 = Vault.open(tmp_path / "v.vault", "nueva-contraseña")
    assert v2.read_thumb(e.id)[:2] == b"\xff\xd8"  # la MK sobrevivió al cambio


def test_locked_vault_refuses_operations(tmp_path, vault):
    e = _import(vault, make_photo(tmp_path))
    vault.lock()
    assert vault.is_locked
    with pytest.raises((VaultError, KeyError)):
        vault.read_thumb(e.id)


def test_tiny_file(tmp_path, vault):
    p = tmp_path / "chico.jpg"
    p.write_bytes(b"abc")
    e = vault.import_file(p, "image", None)
    r = vault.open_reader(e.id)
    assert r.read(-1) == b"abc"


def test_folders_roundtrip_and_persistence(tmp_path, vault):
    vault.create_folder("Vacaciones-Secretas")
    e1 = _import(vault, make_photo(tmp_path, "a.png"))
    e2 = _import(vault, make_photo(tmp_path, "b.png"))
    vault.move_files([e1.id], "Vacaciones-Secretas")

    assert [x.id for x in vault.entries("Vacaciones-Secretas")] == [e1.id]
    assert [x.id for x in vault.entries("")] == [e2.id]
    assert len(vault.entries()) == 2  # None = todo

    # las carpetas sobreviven a cerrar y reabrir (viven en el índice cifrado)
    vault.lock()
    v2 = Vault.open(tmp_path / "v.vault", PW)
    assert v2.folders() == ["Vacaciones-Secretas"]
    assert v2.get(e1.id).folder == "Vacaciones-Secretas"

    # y su nombre JAMÁS aparece en claro en el disco
    for f in (tmp_path / "v.vault").rglob("*"):
        if f.is_file():
            assert b"Vacaciones-Secretas" not in f.read_bytes()


def test_import_directly_into_folder(tmp_path, vault):
    vault.create_folder("Album")
    e = vault.import_file(make_photo(tmp_path), "image", None, folder="Album")
    assert vault.entries("Album")[0].id == e.id


def test_delete_folder_moves_content_to_root(tmp_path, vault):
    vault.create_folder("Temp")
    e = vault.import_file(make_photo(tmp_path), "image", None, folder="Temp")
    vault.delete_folder("Temp")
    assert vault.folders() == []
    assert vault.get(e.id).folder == ""          # el archivo NO se borró
    assert vault.entries("")[0].id == e.id


def test_marks_persist_encrypted(tmp_path, vault):
    src = make_big_file(tmp_path)
    e = vault.import_file(src, "video", None)
    # acepta enteros, pares [ms, etiqueta] y tríos [ms, etiqueta, rotación];
    # ordena y deduplica por tiempo
    vault.set_marks(e.id, [90000, [5000, "inicio"], 5000, (30000, "gol", 180)])
    assert vault.get(e.id).marks == [
        [5000, "", None], [30000, "gol", 180], [90000, "", None]]
    vault.lock()
    v2 = Vault.open(tmp_path / "v.vault", PW)           # persisten entre sesiones
    assert v2.get(e.id).marks == [
        [5000, "", None], [30000, "gol", 180], [90000, "", None]]
    v2.set_marks(e.id, [])                              # y se pueden borrar
    assert v2.get(e.id).marks == []


def test_resume_rotation_favorite_persist(tmp_path, vault):
    e_vid = vault.import_file(make_big_file(tmp_path), "video", None)
    e_img = _import(vault, make_photo(tmp_path))
    vault.set_resume(e_vid.id, 123456)
    vault.set_rotation(e_vid.id, 270)
    vault.set_favorite(e_img.id, True)
    assert [x.id for x in vault.entries(favorites=True)] == [e_img.id]
    vault.lock()
    v2 = Vault.open(tmp_path / "v.vault", PW)
    assert v2.get(e_vid.id).resume_ms == 123456
    assert v2.get(e_vid.id).rotation == 270
    assert v2.get(e_img.id).favorite is True
    assert [x.id for x in v2.entries(favorites=True)] == [e_img.id]
    v2.set_favorite(e_img.id, False)
    assert v2.entries(favorites=True) == []


def test_thumb_rotation_and_scale_independent(tmp_path, vault):
    e = _import(vault, make_photo(tmp_path))
    vault.rotate_thumbs([e.id])
    vault.rotate_thumbs([e.id])
    vault.set_thumb_scale([e.id], 2.0)
    assert vault.get(e.id).thumb_rotation == 180
    assert vault.get(e.id).rotation == 0        # girar el thumb NO gira el contenido
    vault.set_rotation(e.id, 90)
    assert vault.get(e.id).thumb_rotation == 180  # ni al revés
    vault.lock()
    v2 = Vault.open(tmp_path / "v.vault", PW)     # ambos persisten por separado
    assert v2.get(e.id).thumb_rotation == 180
    assert v2.get(e.id).thumb_scale == 2.0
    assert v2.get(e.id).rotation == 90


class _FakeRemoteStore:
    """Adaptador de pruebas: sirve una bóveda local a través de la interfaz
    de almacén remoto (read_header/read_index/read), igual que DriveStore.
    Ejercita todo el camino remoto excepto el transporte HTTP."""

    writable = False
    name = "prueba-remota"

    def read_header(self):
        return (self.root / "header.json").read_bytes()

    def read_index(self):
        return (self.root / "index.enc").read_bytes()

    def __init__(self, root):
        self.root = Path(root)
        self.prefetched: list = []
        self.downloaded: set = set()
        self.cancels = 0

    def read(self, blob_id):
        self.downloaded.add(blob_id)
        return (self.root / "blobs" / blob_id[:2] / f"{blob_id}.blob").read_bytes()

    def prefetch(self, blob_ids):
        self.prefetched.extend(blob_ids)

    def cancel_prefetch(self):
        self.cancels += 1

    def available_blobs(self):
        return {p.stem for p in (self.root / "blobs").rglob("*.blob")}

    def refresh(self):
        pass


def test_remote_availability_flags(tmp_path, vault):
    """Con una subida a medias, los elementos incompletos deben detectarse
    sin descargar contenido (solo inventario de blobs presentes)."""
    ev = vault.import_file(make_big_file(tmp_path), "video", None)   # 3 chunks
    ep = _import(vault, make_photo(tmp_path))
    vault.lock()
    store = _FakeRemoteStore(tmp_path / "v.vault")
    rv = Vault.open_remote(store, PW)

    st = rv.availability()
    assert st == {ev.id: True, ep.id: True}

    # simular que a un video aún le falta un chunk por subir
    missing = rv.get(ev.id).chunks[1]
    (tmp_path / "v.vault" / "blobs" / missing[:2] / f"{missing}.blob").unlink()
    st = rv.availability(refresh=True)
    assert st[ev.id] is False and st[ep.id] is True

    # una bóveda local no reporta disponibilidad (siempre completa)
    v2 = Vault.open(tmp_path / "v.vault", PW)
    assert v2.availability() is None


def test_remote_readonly_streaming_and_guards(tmp_path, vault):
    src = make_big_file(tmp_path)
    ev = vault.import_file(src, "video", None)
    ep = _import(vault, make_photo(tmp_path))
    vault.set_marks(ev.id, [[1000, "x", 90]])
    vault.lock()

    store = _FakeRemoteStore(tmp_path / "v.vault")
    with pytest.raises(cc.VaultCryptoError):
        Vault.open_remote(store, "incorrecta")
    rv = Vault.open_remote(store, PW)
    assert rv.read_only and rv.root is None
    assert {x.id for x in rv.entries()} == {ev.id, ep.id}
    assert rv.get(ev.id).marks == [[1000, "x", 90]]

    # streaming con seek + miniaturas + exportar: permitidos e íntegros
    original = src.read_bytes()
    r = rv.open_reader(ev.id)
    r.seek(cc.CHUNK_SIZE + 7)
    assert r.read(50) == original[cc.CHUNK_SIZE + 7: cc.CHUNK_SIZE + 57]
    # lectura adelantada: al tocar el chunk 1, se pidieron los siguientes
    assert store.prefetched, "el lector no pre-cargó chunks"
    assert set(store.prefetched) <= set(rv.get(ev.id).chunks)
    # mapa de buffer: por ahora solo está bajado el chunk central (1 de 3)
    assert r.buffered_ranges() == [(1 / 3, 2 / 3)]
    # salto de reproducción: a un chunk VECINO no cancela; a uno lejano sí
    r.seek(0)
    r.read(5)                              # 1 -> 0: vecino
    cancels0 = store.cancels
    r.seek(2 * cc.CHUNK_SIZE + 1)
    r.read(5)                              # 0 -> 2: salto detectado
    assert store.cancels > cancels0, "el salto no canceló pre-cargas"
    # prefetch_ahead es idempotente y respeta la ventana
    r.prefetch_ahead(2)
    assert set(store.prefetched) <= set(rv.get(ev.id).chunks)
    r.seek(0)
    assert r.read(-1) == original
    assert r.buffered_ranges() == [(0.0, 1.0)]   # ahora sí: entero bajado
    assert rv.read_thumb(ep.id)[:2] == b"\xff\xd8"
    out = tmp_path / "out"
    out.mkdir()
    assert rv.export_file(ev.id, out).read_bytes() == original

    # escrituras estructurales: prohibidas con error claro
    with pytest.raises(VaultError):
        rv.import_file(src, "video", None)
    with pytest.raises(VaultError):
        rv.create_folder("X")
    with pytest.raises(VaultError):
        rv.delete_file(ev.id)
    # metadata de sesión: no-op silencioso (el visor no debe romperse)
    rv.set_marks(ev.id, [])
    rv.set_favorite(ep.id, True)
    rv.set_resume(ev.id, 999)
    assert rv.get(ev.id).marks == [[1000, "x", 90]]
    assert rv.get(ep.id).favorite is False
    assert rv.get(ev.id).resume_ms == 0


def test_import_bytes_and_set_thumb(tmp_path, vault):
    # importar desde RAM (captura de fotograma): roundtrip bit a bit
    data = os.urandom(200_000)
    thumb1 = b"\xff\xd8" + b"t1" * 100
    e = vault.import_bytes("captura.jpg", data, "image", thumb1)
    assert e.name == "captura.jpg" and e.size == len(data)
    r = vault.open_reader(e.id)
    assert r.read(-1) == data
    assert vault.read_thumb(e.id) == thumb1

    # reemplazar la miniatura: blob nuevo, el antiguo desaparece del disco
    old_blob = vault.get(e.id).thumb
    thumb2 = b"\xff\xd8" + b"t2" * 120
    vault.set_thumb(e.id, thumb2)
    assert vault.read_thumb(e.id) == thumb2
    assert vault.get(e.id).thumb != old_blob
    assert not vault.store.path_for(old_blob).exists()

    # persiste tras reabrir
    vault.lock()
    v2 = Vault.open(tmp_path / "v.vault", PW)
    assert v2.read_thumb(e.id) == thumb2
    assert v2.open_reader(e.id).read(-1) == data


def test_adjust_and_flip_persist(tmp_path, vault):
    e = _import(vault, make_photo(tmp_path))
    assert vault.get(e.id).adjust == {} and not vault.get(e.id).flip_h
    vault.set_adjust(e.id, {"brightness": 30, "gamma": -20, "smooth": True})
    vault.set_flip(e.id, True, False)
    vault.lock()
    v2 = Vault.open(tmp_path / "v.vault", PW)
    assert v2.get(e.id).adjust == {"brightness": 30, "gamma": -20, "smooth": True}
    assert v2.get(e.id).flip_h is True and v2.get(e.id).flip_v is False
    # remota: no-op silencioso
    rv = Vault.open_remote(_FakeRemoteStore(tmp_path / "v.vault"), PW)
    rv.set_adjust(e.id, {})
    rv.set_flip(e.id, False, True)
    assert rv.get(e.id).adjust == {"brightness": 30, "gamma": -20, "smooth": True}
    assert rv.get(e.id).flip_h is True


def test_filter_params_roundtrip():
    from vaultjam.ui.filters import FilterParams
    p = FilterParams(brightness=10, gamma=-5, smooth=True)
    d = p.to_dict()
    assert d == {"brightness": 10, "gamma": -5, "smooth": True}
    q = FilterParams.from_dict(d)
    assert (q.brightness, q.gamma, q.smooth, q.contrast) == (10, -5, True, 0)
    assert FilterParams().to_dict() == {}
    assert FilterParams.from_dict(None).neutral()


def test_priority_gate_video_first():
    """Las descargas de fondo (miniaturas) esperan a que el primer plano
    (video) termine: el video manda."""
    import threading as th
    import time as tm

    from vaultjam.gdrive import _PriorityGate
    gate = _PriorityGate()
    order: list = []
    gate.enter_fg()                      # video descargando

    def bg():
        gate.wait_for_fg_idle()
        order.append("miniatura")

    t = th.Thread(target=bg)
    t.start()
    tm.sleep(0.15)
    order.append("video-listo")
    gate.exit_fg()                       # el video terminó: paso libre
    t.join(3)
    assert order == ["video-listo", "miniatura"]
    # sin primer plano activo, el fondo no espera nada
    t0 = tm.monotonic()
    gate.wait_for_fg_idle()
    assert tm.monotonic() - t0 < 0.2


def test_neutral_filters_do_not_touch_pixels():
    """Garantía: con los controles por defecto, la imagen NO se altera —
    apply_filters devuelve el MISMO objeto, sin copia ni procesado."""
    from PySide6.QtGui import QImage

    from vaultjam.ui.filters import FilterParams, apply_filters
    img = QImage(20, 20, QImage.Format.Format_RGB32)
    img.fill(0xFF345678)
    assert FilterParams().neutral()
    assert apply_filters(img, FilterParams()) is img
    # y cualquier control movido deja de ser neutro (sí procesa)
    assert apply_filters(img, FilterParams(brightness=1)) is not img


def test_pin_curtain(tmp_path, vault):
    assert not vault.has_pin
    with pytest.raises(VaultError):
        vault.set_pin(None, "12a4")     # debe ser numérico
    with pytest.raises(VaultError):
        vault.set_pin(None, "12345")    # y de 4 dígitos exactos
    vault.set_pin(None, "1234")
    assert vault.has_pin
    assert vault.check_pin("1234") and not vault.check_pin("0000")
    with pytest.raises(VaultError):
        vault.set_pin("9999", "5678")   # cambiar exige el PIN antiguo
    vault.set_pin("1234", "5678")
    assert vault.check_pin("5678") and not vault.check_pin("1234")

    # persiste dentro del índice cifrado (nunca en claro: se guarda hasheado)
    vault.lock()
    v2 = Vault.open(tmp_path / "v.vault", PW)
    assert v2.has_pin and v2.check_pin("5678")

    # llave de escape: la contraseña maestra autoriza sin el PIN antiguo
    assert v2.verify_password(PW) and not v2.verify_password("mala")
    with pytest.raises(VaultError):
        v2.set_pin(None, "1111")                    # sin PIN ni contraseña: no
    with pytest.raises(VaultError):
        v2.set_pin(None, "1111", password="mala")   # contraseña mala: tampoco
    v2.set_pin(None, "1111", password=PW)           # PIN olvidado -> restablecer
    assert v2.check_pin("1111")
    with pytest.raises(VaultError):
        v2.remove_pin(old="0000")                   # quitar exige autorización
    v2.remove_pin(password=PW)                      # ...o la contraseña
    assert not v2.has_pin
    v2.set_pin(None, "2222")                        # sin PIN previo: directo
    v2.remove_pin(old="2222")                       # quitar con el PIN actual
    assert not v2.has_pin
    v2.lock()
    v3 = Vault.open(tmp_path / "v.vault", PW)
    assert not v3.has_pin                           # la eliminación persiste
    v3.set_pin(None, "5678")

    # bóveda remota: el PIN llega con el índice y los cambios son de sesión
    store = _FakeRemoteStore(tmp_path / "v.vault")
    rv = Vault.open_remote(store, PW)
    assert rv.has_pin and rv.check_pin("5678")
    rv.set_pin("5678", "1111")          # permitido, pero no persiste en disco
    assert rv.check_pin("1111")
    assert rv.verify_password(PW)       # la llave de escape también en remoto
    rv2 = Vault.open_remote(store, PW)
    assert rv2.check_pin("5678")        # el remoto sigue con el original


def test_folder_validation(tmp_path, vault):
    with pytest.raises(VaultError):
        vault.create_folder("con/barra")
    with pytest.raises(VaultError):
        vault.create_folder("   ")
    vault.create_folder("Unica")
    with pytest.raises(VaultError):
        vault.create_folder("Unica")             # duplicada
    e = _import(vault, make_photo(tmp_path))
    with pytest.raises(VaultError):
        vault.move_files([e.id], "NoExiste")
