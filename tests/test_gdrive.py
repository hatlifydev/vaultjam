"""Regresión de concurrencia del almacén Drive: una llamada de red lenta
(listar o descargar) NO debe bloquear a otro hilo. Antes, `_list` sostenía
el lock durante el HTTP, así que abrir un video mientras una miniatura
listaba su subcarpeta dejaba al video colgado."""

import threading
import time

import pytest

from vaultjam.gdrive import DriveStore


class _FakeExec:
    def __init__(self, store_svc, folder_id):
        self._svc = store_svc
        self._fid = folder_id

    def execute(self, **_):
        gate = self._svc.block.get(self._fid)
        if gate is not None:
            gate.wait(5)          # simula una respuesta de red lenta
        files = self._svc.tree.get(self._fid, [])
        return {"files": [{"id": f"{self._fid}/{n}", "name": n} for n in files]}


class _FakeFiles:
    def __init__(self, svc):
        self._svc = svc

    def list(self, q, **_):
        # q = "'<folder_id>' in parents and trashed=false"
        fid = q.split("'", 2)[1]
        return _FakeExec(self._svc, fid)


class _FakeSvc:
    """Un cliente por hilo (como los reales); comparten árbol y compuertas."""

    def __init__(self, tree, block):
        self.tree = tree
        self.block = block

    def files(self):
        return _FakeFiles(self)


def test_list_does_not_hold_lock_during_network():
    tree = {
        "root": ["header.json", "index.enc", "blobs"],
        "blobs": ["3f", "a1"],
        "3f": ["chunkA.blob"],
        "a1": ["chunkB.blob"],
    }
    slow = threading.Event()          # la subcarpeta "3f" responde lento
    block = {"3f": slow}
    store = DriveStore(_FakeSvc(tree, block), "root", "v",
                       service_factory=lambda: _FakeSvc(tree, block))

    done = threading.Event()

    def slow_listing():
        store._list("3f")             # se quedará esperando en slow.wait()

    t = threading.Thread(target=slow_listing)
    t.start()
    time.sleep(0.2)                   # asegurar que ya está dentro del listado

    # Otro hilo lista una carpeta distinta: NO debe bloquearse por el lento.
    t0 = time.monotonic()
    result = store._list("a1")
    elapsed = time.monotonic() - t0
    assert "chunkB.blob" in result
    assert elapsed < 1.0, f"un listado quedó bloqueado por otro ({elapsed:.1f}s)"

    slow.set()                        # liberar el lento
    t.join(5)
    assert not t.is_alive()


def test_thread_svc_is_per_thread():
    tree = {"root": ["header.json", "blobs"], "blobs": []}
    made: list = []
    store = DriveStore(_FakeSvc(tree, {}), "root", "v",
                       service_factory=lambda: made.append(1) or _FakeSvc(tree, {}))
    seen = {}
    ready = threading.Barrier(2)

    def grab(key):
        ready.wait(5)                 # los dos vivos a la vez: sin reuso de id
        seen[key] = store._thread_svc()   # guardar el objeto (mantenerlo vivo)

    a = threading.Thread(target=grab, args=("a",))
    b = threading.Thread(target=grab, args=("b",))
    a.start(); b.start(); a.join(); b.join()
    assert seen["a"] is not seen["b"], "dos hilos comparten cliente HTTP"
