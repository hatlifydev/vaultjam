"""Traer desde la nube: importar/espejar entradas de una bóveda de Google
Drive hacia la bóveda LOCAL abierta. Es la dirección INVERSA de gsync.py.

Dos modos, autodetectados comparando la clave maestra (Vault.same_master_key):

  - ESPEJO (misma bóveda): las dos comparten clave maestra, así que los
    blobs remotos ya están cifrados con la clave de destino. Se copia el
    CIPHERTEXT de los que falten conservando su id y se injertan las
    entradas ausentes en el índice local. No descifra nada: es un
    respaldo→local eficiente (rellena lo que le falte a tu copia local).

  - IMPORTAR (bóveda distinta): claves distintas. Se descifra el contenido
    de la bóveda de ORIGEN en RAM (con SU clave) y se reingiere re-cifrado
    bajo la clave de DESTINO (blobs e id nuevos). El texto plano nunca toca
    el disco (igual que el visor); dedup por (nombre, tamaño, fecha).

Propiedades:
  - Solo LEE Drive (basta OAuth de solo lectura); todo lo que escribe es
    local. No modifica ni la bóveda de origen ni el espejo remoto.
  - Unión, nunca destructivo: jamás borra nada de la bóveda local. Traer es
    reanudable e idempotente (el dedup evita duplicar al reintentar).
  - Cancelable ENTRE elementos (un elemento en curso termina su archivo).
"""

from __future__ import annotations

import concurrent.futures as cf
import threading

PARALLEL_WORKERS = 6   # igual que la subida: el cuello es la latencia, no la CPU


class CloudImport:
    def __init__(self, src_vault, dst_vault):
        """src_vault: bóveda remota abierta en solo lectura (Vault.open_remote).
        dst_vault: bóveda local abierta con escritura (destino)."""
        self.src = src_vault
        self.dst = dst_vault
        self.same_vault = dst_vault.same_master_key(src_vault)

    @property
    def mode(self) -> str:
        return "espejo" if self.same_vault else "importar"

    def source_by_folder(self) -> dict[str, list]:
        """Entradas de la bóveda de origen agrupadas por carpeta (para la
        pantalla de selección). No descarga contenido: la metadata ya está
        en el índice descifrado en RAM."""
        out: dict[str, list] = {}
        for e in self.src.entries():
            out.setdefault(e.folder, []).append(e)
        return out

    def _do_one(self, eid, folder_override, should_stop):
        """Trae UN elemento (se ejecuta en un hilo del pool). Toda la I/O de
        red y el cifrado ocurren aquí, en paralelo; el alta en el índice la
        serializa el propio Vault con su lock estrecho. Devuelve la clave del
        contador ('añadidos'|'reparados'|'importados'|'omitidos') y la
        entrada, o None si se saltó por parada."""
        if should_stop():
            return None
        e = self.src.get(eid)   # KeyError improbable: ids vienen del origen
        if self.same_vault:
            r = self.dst.graft_ciphertext_entry(e, self.src.store, should_stop)
            key = {"added": "añadidos", "repaired": "reparados",
                   "skipped": "omitidos"}[r]
        else:
            new = self.dst.import_decrypted_entry(
                self.src, e, folder=folder_override, cancelled=should_stop)
            key = "omitidos" if new is None else "importados"
        return key, e

    def run(self, selected_ids, *, folder_override: str | None = None,
            workers: int = PARALLEL_WORKERS,
            progress=lambda done, total: None,
            status=lambda msg: None,
            cancelled=lambda: False,
            item_done=lambda entry: None) -> dict:
        """Trae los elementos seleccionados EN PARALELO (pool de `workers`
        hilos), igual que la subida: el límite es la latencia por petición,
        no la CPU. folder_override (solo modo importar) mete todo en una
        carpeta destino; None conserva la de origen. En modo espejo se ignora.

        Las descargas/descifrado/escritura corren en los hilos del pool; los
        callbacks (progress/status/item_done) se invocan SIEMPRE desde este
        hilo orquestador conforme completan, para que la UI reciba señales
        desde un único hilo (como hace el sincronizador de subida)."""
        ids = list(dict.fromkeys(selected_ids))
        total = len(ids)
        progress(0, total)
        counters = {"añadidos": 0, "reparados": 0, "importados": 0, "omitidos": 0}
        errors: list[str] = []
        stop = threading.Event()

        def should_stop():
            return stop.is_set() or cancelled()

        verbo = "Copiando" if self.same_vault else "Importando"
        done = 0
        with cf.ThreadPoolExecutor(
                max_workers=max(1, int(workers)),
                thread_name_prefix="vj-pull") as ex:
            futs = {ex.submit(self._do_one, eid, folder_override, should_stop): eid
                    for eid in ids}
            for fut in cf.as_completed(futs):
                if cancelled() and not stop.is_set():
                    stop.set()   # las tareas no arrancadas se descartan al iniciar
                done += 1
                try:
                    res = fut.result()
                except Exception as exc:  # noqa: BLE001 — un fallo no aborta el lote
                    errors.append(str(exc))
                    res = None
                if res is not None:
                    key, e = res
                    counters[key] += 1
                    item_done(e)
                status(f"{verbo}… {done} de {total} ({max(1, int(workers))} en paralelo)")
                progress(done, total)
        return {
            "cancelado": bool(cancelled()),
            "modo": self.mode,
            **counters,
            "errores": errors, "total": total,
        }
