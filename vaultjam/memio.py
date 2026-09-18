"""QIODevice que descifra bajo demanda, exclusivamente en RAM.

Es el puente entre el ChunkReader de la bóveda y QMediaPlayer: Qt "tira" de
este dispositivo como si fuera un archivo, y cada lectura descifra (y
VERIFICA con GCM) solo los chunks necesarios. Nunca existe una copia
completa del video en claro: ni en disco (jamás) ni en RAM (solo la ventana
de la caché LRU del reader, ~8 MiB).
"""

from __future__ import annotations

from PySide6.QtCore import QIODevice

from .vault import ChunkReader


class DecryptingIODevice(QIODevice):
    def __init__(self, reader: ChunkReader, parent=None):
        super().__init__(parent)
        self._reader = reader
        self.open(QIODevice.OpenModeFlag.ReadOnly)

    # Qt necesita saber que puede hacer seek (los demuxers de video saltan
    # constantemente entre el moov/índice y los datos).
    def isSequential(self) -> bool:  # noqa: N802 (API de Qt)
        return False

    def size(self) -> int:
        return self._reader.size

    def bytesAvailable(self) -> int:  # noqa: N802
        return (self._reader.size - self.pos()) + super().bytesAvailable()

    def seek(self, pos: int) -> bool:
        if pos < 0 or pos > self._reader.size:
            return False
        super().seek(pos)
        return True

    def readData(self, maxlen: int) -> bytes:  # noqa: N802
        # QIODevice lleva la posición lógica; el reader es thread-safe y
        # re-posicionable, así que fijamos posición y leemos atómicamente.
        self._reader.seek(self.pos())
        return self._reader.read(min(maxlen, 4 * 1024 * 1024))

    def writeData(self, data) -> int:  # noqa: N802
        return -1  # solo lectura

    def close(self) -> None:
        self._reader.close()  # purga la caché de chunks descifrados
        super().close()
