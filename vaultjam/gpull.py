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

    def run(self, selected_ids, *, folder_override: str | None = None,
            progress=lambda done, total: None,
            status=lambda msg: None,
            cancelled=lambda: False,
            item_done=lambda entry: None) -> dict:
        """Trae los elementos seleccionados. folder_override (solo modo
        importar) mete todo en una carpeta de destino concreta; None conserva
        la carpeta de origen. En modo espejo se ignora (los ids deben coincidir
        exactamente con los del origen)."""
        ids = list(dict.fromkeys(selected_ids))
        total = len(ids)
        progress(0, total)
        added = repaired = imported = skipped = 0
        errors: list[str] = []
        for i, eid in enumerate(ids):
            if cancelled():
                break
            try:
                e = self.src.get(eid)
            except KeyError:
                continue
            verbo = "Copiando" if self.same_vault else "Importando"
            status(f"{verbo} «{e.name}» ({i + 1} de {total})…")
            try:
                if self.same_vault:
                    r = self.dst.graft_ciphertext_entry(e, self.src.store, cancelled)
                    if r == "added":
                        added += 1
                    elif r == "repaired":
                        repaired += 1
                    else:
                        skipped += 1
                else:
                    new = self.dst.import_decrypted_entry(
                        self.src, e, folder=folder_override, cancelled=cancelled)
                    if new is None:
                        skipped += 1
                    else:
                        imported += 1
                item_done(e)
            except Exception as ex:  # noqa: BLE001 — un fallo por elemento no aborta el lote
                errors.append(f"{e.name}: {ex}")
            progress(i + 1, total)
        return {
            "cancelado": bool(cancelled()),
            "modo": self.mode,
            "añadidos": added, "reparados": repaired,
            "importados": imported, "omitidos": skipped,
            "errores": errors, "total": total,
        }
