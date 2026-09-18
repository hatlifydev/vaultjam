"""Sincronización local → Google Drive: espejo cifrado de la bóveda.

Modelo: la bóveda LOCAL es la original; Drive es un espejo de solo lectura.
Un único escritor (este sincronizador) elimina el riesgo de conflictos.

Propiedades del algoritmo:

  - Reanudable: compara el inventario local (según el índice) con lo ya
    presente en Drive y sube SOLO lo que falta. Cancelar es inofensivo.
  - Autocorrector: un blob remoto con tamaño incorrecto (subida web a
    medias, corrupción) se re-sube. Todos los blobs miden exactamente
    CHUNK + nonce + tag, así que la verificación por tamaño es exacta.
  - Commit al final: el índice se sube el ÚLTIMO, cuando todos los blobs
    que referencia ya están en Drive. Un lector remoto nunca ve un índice
    apuntando a blobs inexistentes.
  - Verificación final: se re-lista el espejo y se comprueba que no falte
    nada antes de declarar éxito.
  - Solo mueve ciphertext: no necesita la clave de la bóveda para nada
    (por eso incluso puede seguir subiendo con la bóveda ya bloqueada).
"""

from __future__ import annotations

from pathlib import Path

from . import crypto_core as cc

EXPECTED_BLOB_SIZE = cc.CHUNK_SIZE + cc.NONCE_LEN + cc.TAG_LEN
_FOLDER_MT = "application/vnd.google-apps.folder"


class DriveOps:
    """Capa fina sobre la API de Drive con las únicas operaciones que la
    sincronización necesita (sustituible por una implementación en memoria
    en las pruebas). Todas las llamadas usan reintentos automáticos."""

    RETRIES = 5

    def __init__(self, service):
        self._svc = service

    def find_folders(self, name: str) -> list[str]:
        esc = name.replace("\\", "\\\\").replace("'", "\\'")
        q = f"name='{esc}' and mimeType='{_FOLDER_MT}' and trashed=false"
        res = self._svc.files().list(q=q, fields="files(id)",
                                     pageSize=10).execute(num_retries=self.RETRIES)
        return [f["id"] for f in res.get("files", [])]

    def folder_exists(self, folder_id: str) -> bool:
        try:
            meta = self._svc.files().get(
                fileId=folder_id, fields="id,mimeType,trashed"
            ).execute(num_retries=self.RETRIES)
            return meta.get("mimeType") == _FOLDER_MT and not meta.get("trashed")
        except Exception:
            return False

    def create_folder(self, parent_id: str | None, name: str) -> str:
        body = {"name": name, "mimeType": _FOLDER_MT}
        if parent_id:
            body["parents"] = [parent_id]
        return self._svc.files().create(
            body=body, fields="id").execute(num_retries=self.RETRIES)["id"]

    def list_children(self, folder_id: str) -> dict[str, dict]:
        out: dict[str, dict] = {}
        token = None
        while True:
            res = self._svc.files().list(
                q=f"'{folder_id}' in parents and trashed=false",
                fields="nextPageToken,files(id,name,size)",
                pageSize=1000, pageToken=token).execute(num_retries=self.RETRIES)
            for f in res.get("files", []):
                size = int(f["size"]) if "size" in f and f["size"] is not None else None
                out[f["name"]] = {"id": f["id"], "size": size}
            token = res.get("nextPageToken")
            if not token:
                break
        return out

    def upload(self, parent_id: str, name: str, path: Path,
               existing_id: str | None = None) -> str:
        from googleapiclient.http import MediaFileUpload
        media = MediaFileUpload(str(path), mimetype="application/octet-stream")
        if existing_id:
            self._svc.files().update(
                fileId=existing_id, media_body=media
            ).execute(num_retries=self.RETRIES)
            return existing_id
        return self._svc.files().create(
            body={"name": name, "parents": [parent_id]},
            media_body=media, fields="id").execute(num_retries=self.RETRIES)["id"]


class DriveSyncer:
    def __init__(self, ops, root: Path, expected_blob_ids: list[str],
                 folder_name: str | None = None, folder_hint: str | None = None):
        self.ops = ops
        self.root = Path(root)
        self.expected = list(dict.fromkeys(expected_blob_ids))
        self.folder_name = folder_name or self.root.name
        self.folder_hint = folder_hint

    def _resolve_folder(self, create: bool = True) -> str:
        # 1) la carpeta usada la última vez, si sigue existiendo
        if self.folder_hint and self.ops.folder_exists(self.folder_hint):
            return self.folder_hint
        # 2) por nombre; ambigüedad = error claro, jamás adivinar
        ids = self.ops.find_folders(self.folder_name)
        if len(ids) == 1:
            return ids[0]
        if len(ids) > 1:
            raise RuntimeError(
                f"Hay {len(ids)} carpetas llamadas «{self.folder_name}» en tu "
                "Drive; deja solo una (o vacía la papelera) y reintenta.")
        if not create:
            raise RuntimeError(
                f"No existe todavía un espejo «{self.folder_name}» en Drive: "
                "sincroniza primero con ☁.")
        # 3) no existe: se crea en la raíz de Mi unidad
        return self.ops.create_folder(None, self.folder_name)

    def mirrored_blobs(self) -> tuple[str, set[str]]:
        """Solo VERIFICA (no crea ni sube nada): devuelve la carpeta espejo
        y el conjunto de blobs correctos (tamaño exacto) presentes en Drive.
        Es la base de los marcos verde/rojo en la bóveda local."""
        fid = self._resolve_folder(create=False)
        blobs_meta = self.ops.list_children(fid).get("blobs")
        if not blobs_meta:
            return fid, set()
        remote, _ = self._inventory(blobs_meta["id"])
        return fid, {b for b, m in remote.items()
                     if m.get("size") == EXPECTED_BLOB_SIZE}

    def _inventory(self, blobs_id: str) -> tuple[dict[str, dict], dict[str, str]]:
        remote: dict[str, dict] = {}
        sub_ids: dict[str, str] = {}
        for name, meta in self.ops.list_children(blobs_id).items():
            if len(name) == 2:
                sub_ids[name] = meta["id"]
                for child, m2 in self.ops.list_children(meta["id"]).items():
                    if child.endswith(".blob"):
                        remote[child[:-5]] = m2
        return remote, sub_ids

    def sync(self, progress=lambda done, total: None,
             status=lambda msg: None,
             cancelled=lambda: False) -> dict:
        status("Localizando la carpeta espejo en Drive…")
        fid = self._resolve_folder()
        root_children = self.ops.list_children(fid)
        blobs_meta = root_children.get("blobs")
        blobs_id = blobs_meta["id"] if blobs_meta else self.ops.create_folder(fid, "blobs")

        status("Inventariando el espejo (solo metadata)…")
        remote, sub_ids = self._inventory(blobs_id)

        plan: list[tuple[str, str | None]] = []
        for b in self.expected:
            m = remote.get(b)
            if m is None:
                plan.append((b, None))                 # falta: subir
            elif m.get("size") != EXPECTED_BLOB_SIZE:
                plan.append((b, m["id"]))              # tamaño mal: re-subir
        total = len(plan)
        progress(0, total)

        uploaded = corrected = 0
        for i, (b, existing) in enumerate(plan):
            if cancelled():
                # Cancelar es seguro: el índice NO se ha tocado; lo subido
                # queda aprovechado para la próxima ejecución.
                return {"cancelado": True, "subidos": uploaded,
                        "pendientes": total - i, "total": len(self.expected),
                        "folder_id": fid}
            sub = b[:2]
            sid = sub_ids.get(sub)
            if sid is None:
                sid = self.ops.create_folder(blobs_id, sub)
                sub_ids[sub] = sid
            status(f"Subiendo blob {i + 1} de {total}…")
            self.ops.upload(sid, f"{b}.blob", self.root / "blobs" / sub / f"{b}.blob",
                            existing_id=existing)
            if existing:
                corrected += 1
            uploaded += 1
            progress(uploaded, total)

        # Punto de commit: header y, en último lugar, el índice.
        status("Actualizando header e índice…")
        self.ops.upload(fid, "header.json", self.root / "header.json",
                        existing_id=(root_children.get("header.json") or {}).get("id"))
        self.ops.upload(fid, "index.enc", self.root / "index.enc",
                        existing_id=(root_children.get("index.enc") or {}).get("id"))

        status("Verificando el espejo…")
        remote2, _ = self._inventory(blobs_id)
        ok = {b for b, m in remote2.items() if m.get("size") == EXPECTED_BLOB_SIZE}
        missing = [b for b in self.expected if b not in ok]
        if missing:
            raise RuntimeError(
                f"Verificación fallida: faltan {len(missing)} blobs tras la "
                "subida. Reintenta la sincronización.")
        return {"cancelado": False, "subidos": uploaded, "corregidos": corrected,
                "ya_presentes": len(self.expected) - uploaded,
                "huerfanos": len(set(remote2) - set(self.expected)),
                "total": len(self.expected), "folder_id": fid,
                "ok_blobs": ok}   # para pintar los marcos verde/rojo
