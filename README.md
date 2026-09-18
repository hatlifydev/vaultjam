# VaultJam — fotos y videos cifrados

Aplicación de escritorio (Windows) que guarda fotos y videos en un
contenedor cifrado con **AES-256-GCM** y contraseña derivada con
**Argon2id**. Sin metadatos en claro: nombres, tamaños, fechas y estructura
viven dentro de un índice cifrado; en disco solo se ven blobs idénticos de
1 MiB con nombres aleatorios.

> ⚠️ Lee [SEGURIDAD.md](SEGURIDAD.md) antes de confiarle nada: explica qué
> protege, qué no, y qué rastros deja Windows fuera del control de la app.

## Funciones

- Crear/abrir bóvedas protegidas por contraseña (sin recuperación posible).
- Importar fotos y videos: se cifran al entrar; los originales no se tocan.
- Galería con miniaturas cifradas y slider de zoom (64–512 px).
- Organización por carpetas: barra lateral con «Todo» / «Sin carpeta» /
  carpetas propias, importar directo a la carpeta activa, mover elementos
  entre carpetas y eliminar carpetas (su contenido vuelve a «Sin carpeta»,
  sin borrar archivos). Los nombres de carpeta son metadata: viven solo en
  el índice cifrado, no como directorios reales en disco.
- Visor integrado: fotos y videos se descifran **solo en RAM**, nunca se
  escriben temporales en claro. Los videos se descifran por trozos bajo
  demanda (~8 MiB de ventana).
- Visor unificado con lista de reproducción: recorre lo que muestra la
  galería (respetando la carpeta activa) mezclando fotos y videos, con
  flechas superpuestas invisibles ‹ › en los bordes (aparecen al pasar el
  ratón) y `AvPág`/`RePág`. En fotos, `←`/`→` también navegan. GIF animados
  incluidos (QMovie en RAM).
- OSD de feedback en cada atajo, ayuda de atajos con `H` o `?`, cursor
  oculto en pantalla completa tras 2 s, zoom con la rueda anclado al cursor
  y presentación automática con `P` (fotos 5 s, videos completos).
- ⭐ Favoritos: tecla `S` en el visor o clic derecho en la galería; fila
  «Favoritos» en la barra lateral. Persisten en el índice cifrado.
- Video: reanuda donde lo dejaste, marcadores con nombre y con rotación
  propia opcional (clic derecho en el chip: renombrar, guardar/quitar la
  rotación actual, eliminar — al saltar al marcador se aplica su
  orientación por SEGMENTOS: cada chip lleva su propio icono ↻ y cada clic
  en él suma 90° a ese segmento (90→180→270→0→quitar); la rotación rige
  desde ese marcador hasta el siguiente con rotación o el final, y hacia
  atrás rige la base u otro marcador — muescas turquesa en la barra),
  repetición con `L` o el botón 🔁
  (tres estados: 🔂 este video / 🔁 todos los videos de la lista, saltando
  las fotos / apagada), repetición A–B con `B`, y vista previa de
  fotogramas al pasar el ratón por la barra de avance (decodificada en un
  hilo desde el propio lector cifrado).
- La rotación de cada foto/video se recuerda (visor). Las miniaturas tienen
  su PROPIA rotación, independiente (clic derecho → «↻ Girar miniatura
  90°»: girar la miniatura no gira el contenido, ni al revés) y su propio
  tamaño (menú «🔍 Tamaño de miniatura»: 1× / 1.5× / 2× — una miniatura
  puede ser más grande que el resto).
- El campo de contraseña recibe el foco automáticamente al abrir la app,
  al cambiar de pestaña y tras un error de contraseña: teclea y Enter.
- La pantalla de apertura puede recordar las últimas bóvedas (solo las
  RUTAS, en el registro de Windows). Es opcional: la casilla «Recordar las
  últimas bóvedas abiertas» lo activa/desactiva (al desactivar se borra lo
  guardado), y «Olvidar» limpia la lista — ver [SEGURIDAD.md](SEGURIDAD.md).
- Ajustes de imagen (fotos y videos, todo en RAM vía LUTs numpy, coste cero
  en neutro): girar 90°, zoom 1x–8x con paneo, brillo, contraste, gamma,
  color (saturación, hasta blanco y negro), temperatura frío/cálido,
  nitidez/suavizado, e interruptor «Suavizar» (desactivado por defecto: se
  ven los píxeles reales al escalar; actívalo para interpolar). Botón
  «Restablecer» vuelve todo a neutro.
- Pantalla completa: botón ⛶, tecla `F` o doble clic; `Esc` para salir.
  Dentro de pantalla completa los controles (ajustes, reproducción y
  marcadores) se ocultan solos y reaparecen al llevar el ratón a la franja
  inferior; en ventana normal están siempre visibles.
- Video: `←`/`→` = ±10 s, velocidad en pasos de 0.25× (`+`/`−`, 0.25×–4×),
  frame a frame (`E`/`R`), espacio = play/pausa, clic directo en la barra
  de avance, y **marcadores persistentes**: `M` o 🔖 añade un marcador en
  la posición actual; aparecen como muescas ámbar en la barra y chips
  clicables que saltan a ese punto (clic derecho en el chip para
  eliminarlo). Se guardan dentro del índice cifrado de la bóveda.
- Anti-captura (interruptor 🕶 en la barra, activado por defecto): la
  galería, los visores y la pantalla de contraseña quedan excluidos de
  capturas, grabación de pantalla, pantalla compartida y Windows Recall
  (`SetWindowDisplayAffinity`, Windows 10 2004+).
- Exportar (descifrar a disco) solo bajo acción explícita, con advertencia.
- Bloqueo manual y automático por inactividad (1/5/15/30 min).

## Ejecutar en desarrollo

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python run_app.py
```

Pruebas (núcleo criptográfico + contenedor, incluidas pruebas de
manipulación activa):

```powershell
.\.venv\Scripts\python -m pytest tests -q
```

## Empaquetar (PyInstaller)

```powershell
.\.venv\Scripts\python -m pip install pyinstaller
.\.venv\Scripts\pyinstaller.exe vaultjam.spec --noconfirm
```

El resultado queda en `dist\VaultJam\VaultJam.exe` (modo carpeta; copia la
carpeta entera). El spec ya recoge los plugins multimedia de Qt y las DLL de
ffmpeg de PyAV.

## Formato del contenedor

```
MiBoveda.vault/
├── header.json    # ÚNICO archivo en claro: params Argon2id, salt y la
│                  # clave maestra envuelta (AES-GCM). Nada del contenido.
├── index.enc      # TODA la metadata, cifrada y con padding a potencia de 2
└── blobs/xx/<128 bits aleatorios>.blob   # todos de exactamente
                   # 1 MiB + 28 B, marcas de tiempo normalizadas
```

Jerarquía de claves: contraseña → Argon2id → KEK → desenvuelve la clave
maestra aleatoria → HKDF → subclaves de contenido / miniaturas / índice.
Cada chunk lleva nonce aleatorio propio y va atado por AAD a su archivo, su
posición y el total (anti-reordenación/truncado). Cambiar la contraseña solo
re-envuelve 32 bytes.

## Ajustar Argon2id

Los parámetros viven en `header.json` de cada bóveda y por defecto son
`m=256 MiB, t=3, p=4` (`vaultjam/crypto_core.py`, `ARGON2_DEFAULTS`):

- **Sube `m_kib` primero**: la memoria es lo que más encarece un ataque con
  GPU. 256 MiB es el mínimo de esta app; 512 MiB–1 GiB si tu equipo va
  sobrado de RAM.
- **`t`** escala el tiempo linealmente: ajusta hasta que desbloquear tarde
  ~0,5–1 s en tu máquina.
- **`p`** ≈ núcleos físicos.

Endurecerlos solo afecta a bóvedas nuevas (o tras cambiar la contraseña);
las existentes guardan sus propios parámetros y siguen abriendo.

## Estructura del código

| Módulo | Responsabilidad |
|---|---|
| `vaultjam/crypto_core.py` | KDF, envoltura de clave, HKDF, sellado/apertura AEAD. Único sitio con criptografía. |
| `vaultjam/vault.py` | Contenedor: header, índice cifrado, importar/exportar/borrar, lector por chunks. |
| `vaultjam/storage.py` | Blobs uniformes, escritura atómica, timestamps normalizados. |
| `vaultjam/thumbs.py` | Miniaturas en RAM (Pillow / PyAV). |
| `vaultjam/memio.py` | `QIODevice` que descifra bajo demanda para el reproductor. |
| `vaultjam/winsec.py` | Anti-captura de pantalla (`SetWindowDisplayAffinity`), best-effort. |
| `vaultjam/ui/` | PySide6: desbloqueo, galería, visor (con `canvas.py`: rotación/zoom/brillo/contraste), ventana principal. |
