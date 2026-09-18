"""Núcleo criptográfico de la bóveda.

REGLA DE ORO de este módulo: aquí NO se implementa ninguna primitiva
criptográfica. Solo se ensamblan primitivas de librerías auditadas:

  - AES-256-GCM  -> cryptography.hazmat.primitives.ciphers.aead.AESGCM
  - Argon2id     -> argon2.low_level.hash_secret_raw (argon2-cffi)
  - HKDF-SHA256  -> cryptography.hazmat.primitives.kdf.hkdf.HKDF

Jerarquía de claves:

  contraseña --Argon2id(salt, params)--> KEK (efímera, nunca se guarda)
  KEK --AES-GCM desenvuelve--> MK (clave maestra aleatoria, guardada envuelta
                                   en el header)
  MK --HKDF--> K_contenido, K_miniaturas, K_indice  (separación de dominios)

Por qué una MK aleatoria en vez de cifrar directo con la clave de la
contraseña: cambiar la contraseña solo re-envuelve 32 bytes (no hay que
recifrar gigas), y la verificación de contraseña es el propio tag GCM del
desenvoltorio — no se almacena ningún hash de la contraseña.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = "BOVEDA"
VERSION = 1

KEY_LEN = 32          # AES-256
SALT_LEN = 16         # salt aleatorio para Argon2id
NONCE_LEN = 12        # 96 bits: el tamaño de nonce estándar de GCM
TAG_LEN = 16

# Tamaño de chunk fijo: TODOS los blobs en disco miden exactamente
# CHUNK_SIZE + NONCE_LEN + TAG_LEN bytes, de modo que ni los tamaños
# individuales ni el número de archivos se puedan inferir del almacén.
CHUNK_SIZE = 1024 * 1024  # 1 MiB

# Parámetros Argon2id por defecto. Se guardan en el header de cada bóveda,
# así que se pueden endurecer en el futuro sin romper bóvedas antiguas.
#
# Cómo ajustarlos:
#   - m_kib (memoria) es el parámetro MÁS importante: castiga los ataques
#     con GPU/ASIC. Súbelo primero, hasta donde la RAM del equipo tolere.
#     262144 KiB = 256 MiB (el mínimo exigido para esta app).
#   - t (iteraciones) escala el tiempo linealmente. Ajústalo para que
#     desbloquear tarde ~0.5-1 s en tu máquina.
#   - p (paralelismo) ~ número de núcleos físicos.
ARGON2_DEFAULTS = {"m_kib": 262144, "t": 3, "p": 4}


class VaultCryptoError(Exception):
    """Fallo de autenticación criptográfica: contraseña incorrecta o datos
    manipulados. No distinguimos ambos casos a propósito: GCM tampoco puede."""


def random_bytes(n: int) -> bytes:
    # os.urandom es el CSPRNG del sistema operativo (BCryptGenRandom en
    # Windows). Única fuente de aleatoriedad de toda la app: salts, claves,
    # nonces e identificadores salen SIEMPRE de aquí, jamás de random/uuid
    # con semillas predecibles.
    return os.urandom(n)


def derive_kek(password: bytes, salt: bytes, m_kib: int, t: int, p: int) -> bytearray:
    """Deriva la KEK desde la contraseña con Argon2id.

    Argon2id (y no Argon2i/d puros) porque combina resistencia a ataques
    side-channel con resistencia a trade-offs de memoria; es la variante
    recomendada por el RFC 9106 para derivación desde contraseñas.
    Devuelve bytearray para poder sobreescribirla (zeroize) al bloquear.
    """
    if len(salt) != SALT_LEN:
        raise ValueError("salt de longitud inesperada")
    raw = hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=t,
        memory_cost=m_kib,
        parallelism=p,
        hash_len=KEY_LEN,
        type=Type.ID,
    )
    return bytearray(raw)


def kdf_aad(m_kib: int, t: int, p: int, salt: bytes, version: int = VERSION) -> bytes:
    """Serialización canónica de los parámetros del KDF, usada como AAD al
    envolver la MK: si un atacante edita el header para debilitar los
    parámetros de Argon2 o cambiar el salt, el desenvoltorio falla con un
    error de autenticación explícito en lugar de comportarse de forma rara."""
    return f"{MAGIC};v={version};argon2id;m={m_kib};t={t};p={p};salt={salt.hex()}".encode()


def wrap_master_key(kek: bytes | bytearray, mk: bytes | bytearray, aad: bytes) -> dict:
    """Envuelve (cifra) la MK con la KEK usando AES-256-GCM."""
    nonce = random_bytes(NONCE_LEN)
    ct = AESGCM(bytes(kek)).encrypt(nonce, bytes(mk), aad)
    return {"nonce": nonce, "ct": ct}


def unwrap_master_key(kek: bytes | bytearray, wrapped: dict, aad: bytes) -> bytearray:
    """Desenvuelve la MK. Un tag GCM inválido significa contraseña incorrecta
    o header manipulado; ambos se reportan igual (indistinguibles por diseño)."""
    try:
        mk = AESGCM(bytes(kek)).decrypt(wrapped["nonce"], wrapped["ct"], aad)
    except InvalidTag as e:
        raise VaultCryptoError(
            "Contraseña incorrecta o cabecera de la bóveda manipulada."
        ) from e
    return bytearray(mk)


@dataclass
class SubKeys:
    """AEADs por dominio, derivados de la MK con HKDF-SHA256.

    Separación de dominios: cada categoría de datos usa una clave distinta,
    de modo que los espacios de nonces son independientes entre categorías y
    un chunk de contenido jamás puede "abrirse" como índice o miniatura ni
    aunque coincidieran nonce y AAD.

    Se guardan los objetos AESGCM (no los bytes de las claves) para minimizar
    copias del material de clave en el heap de Python; al bloquear, basta con
    soltar las referencias (OpenSSL limpia sus estructuras al liberarlas).
    """

    content: AESGCM
    thumbs: AESGCM
    index: AESGCM


def derive_subkeys(mk: bytes | bytearray) -> SubKeys:
    def _hkdf(info: bytes) -> AESGCM:
        # salt=None es correcto aquí: HKDF con salt vacío es seguro cuando el
        # material de entrada (la MK) ya es uniformemente aleatorio, que es
        # exactamente nuestro caso (MK = os.urandom(32)).
        key = HKDF(
            algorithm=hashes.SHA256(), length=KEY_LEN, salt=None, info=info
        ).derive(bytes(mk))
        aead = AESGCM(key)
        return aead

    return SubKeys(
        content=_hkdf(b"boveda/v1/contenido"),
        thumbs=_hkdf(b"boveda/v1/miniaturas"),
        index=_hkdf(b"boveda/v1/indice"),
    )


# ---------------------------------------------------------------------------
# AAD (associated data) por tipo de mensaje.
#
# El AAD ata cada ciphertext a su CONTEXTO: a qué archivo pertenece un chunk,
# en qué posición va y cuántos chunks tiene el archivo. Así, un atacante con
# acceso al disco no puede reordenar chunks, intercambiarlos entre archivos
# ni truncar un archivo sin que la verificación GCM falle.
# ---------------------------------------------------------------------------

def chunk_aad(file_id: bytes, chunk_index: int, total_chunks: int) -> bytes:
    return b"BOVEDA1|chunk|" + file_id + struct.pack(">QQ", chunk_index, total_chunks)


def thumb_aad(file_id: bytes) -> bytes:
    return b"BOVEDA1|thumb|" + file_id


def index_aad() -> bytes:
    return b"BOVEDA1|index"


def seal(aead: AESGCM, plaintext: bytes, aad: bytes) -> bytes:
    """Cifra y autentica un mensaje. Formato: nonce(12) || ciphertext+tag.

    El nonce es SIEMPRE aleatorio y nuevo por mensaje (os.urandom): jamás
    contadores compartidos ni valores derivados, que son la vía clásica de
    reutilización de nonce. Con nonces de 96 bits aleatorios, la cota NIST
    de ~2^32 mensajes por clave queda órdenes de magnitud por encima de
    cualquier bóveda personal (4.000 millones de chunks ≈ 4 PiB).
    """
    nonce = random_bytes(NONCE_LEN)
    return nonce + aead.encrypt(nonce, plaintext, aad)


def open_sealed(aead: AESGCM, blob: bytes, aad: bytes) -> bytes:
    """Descifra y VERIFICA un mensaje sellado. Cualquier alteración del
    nonce, del ciphertext, del tag o del contexto (AAD) lanza excepción:
    nunca se devuelven datos sin autenticar."""
    if len(blob) < NONCE_LEN + TAG_LEN:
        raise VaultCryptoError("Blob demasiado corto: almacenamiento corrupto.")
    try:
        return AESGCM.decrypt(aead, blob[:NONCE_LEN], blob[NONCE_LEN:], aad)
    except InvalidTag as e:
        raise VaultCryptoError(
            "Verificación de integridad fallida: datos corruptos o manipulados."
        ) from e


def zeroize(buf: bytearray | None) -> None:
    """Sobrescribe un buffer sensible. IMPORTANTE — es *best-effort*: Python
    puede haber copiado los datos internamente (str/bytes son inmutables) y
    el recolector no ofrece garantías. Las limitaciones reales se documentan
    en SEGURIDAD.md; aun así, borrar lo que sí controlamos reduce la ventana
    de exposición en RAM."""
    if buf is not None:
        for i in range(len(buf)):
            buf[i] = 0
