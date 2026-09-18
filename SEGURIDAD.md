# Modelo de amenazas y limitaciones honestas

Este documento dice la verdad completa: qué protege la bóveda, qué no, y qué
rastros quedan fuera de su control. Léelo antes de confiar nada sensible.

## Qué usa por dentro (y qué NO)

- **AES-256-GCM** (cifrado autenticado) de la librería `cryptography` para
  todo el contenido, miniaturas e índice. Cualquier bit alterado en disco se
  detecta antes de entregar un solo byte.
- **Argon2id** (`argon2-cffi`, RFC 9106) para derivar la clave desde tu
  contraseña: 256 MiB de memoria, 3 iteraciones, paralelismo 4 (ajustables
  por bóveda, ver README).
- **HKDF-SHA256** para separar subclaves por dominio (contenido / miniaturas
  / índice) a partir de una clave maestra aleatoria.
- **Cero criptografía casera**: esta app solo ensambla esas primitivas.
  Nonces de 96 bits aleatorios (`os.urandom`) nuevos por cada mensaje, salt
  aleatorio por bóveda, claves aleatorias del CSPRNG del sistema.

## Contra qué SÍ protege

| Amenaza | Protección |
|---|---|
| Robo o pérdida del equipo / disco (datos **en reposo**) | Sin la contraseña, contenido, nombres, tamaños, fechas y estructura son indistinguibles de ruido. Es el caso de uso central. |
| Curiosos con acceso ocasional al PC (bóveda **bloqueada**) | Igual que arriba: solo ven blobs uniformes de 1 MiB con nombres aleatorios y fechas normalizadas. |
| Ataques de diccionario contra tu contraseña | Argon2id con 256 MiB por intento hace que probar contraseñas sea carísimo incluso con GPUs. **Pero no salva una contraseña débil** (ver abajo). |
| Manipulación del contenedor (bit flips, chunks reordenados, intercambiados entre archivos, truncados, parámetros KDF debilitados en el header) | GCM + AAD posicional: cualquier alteración produce un error de autenticación explícito. |
| Análisis del contenedor sin clave (¿cuántas fotos? ¿de qué tamaño? ¿qué nombres?) | Todos los blobs son idénticos (1 MiB), el índice va cifrado y con padding a potencias de 2, las marcas de tiempo van normalizadas. Solo se filtra el **volumen total** aproximado. |

## Contra qué NO protege (sé honesto contigo mismo)

| Amenaza | Realidad |
|---|---|
| **Malware / keylogger en tu PC** | Pierdes. Un keylogger captura la contraseña al teclearla; un troyano con tus privilegios lee la RAM de la app con la bóveda abierta. Ninguna app de usuario puede defenderse de un sistema comprometido. |
| **Forense de RAM / DMA con la bóveda abierta** | Las claves y el contenido visualizado están necesariamente en RAM mientras la usas. El bloqueo automático reduce la ventana; no la elimina. |
| **Contraseña débil o reutilizada** | Argon2id encarece cada intento, pero "hola1234" cae igual. La única defensa real es una frase larga y única. No hay recuperación: contraseña olvidada = datos perdidos para siempre (por diseño). |
| **Ataque de reversión (rollback)** | Alguien con acceso de escritura al disco puede restaurar la bóveda entera a un estado anterior válido (p. ej. resucitar un archivo que borraste). GCM no puede impedirlo sin un ancla de confianza externa. |
| **Capturas de pantalla / grabación / mirar por encima del hombro** | Mitigado en parte: con el anti-captura activado (🕶, por defecto), las ventanas de la app salen en negro en capturas, grabaciones, pantalla compartida y Windows Recall (`SetWindowDisplayAffinity`). Pero NO protege contra malware con drivers de kernel, ni contra una cámara apuntando a la pantalla, ni si desactivas el interruptor. |
| **Coacción** | La bóveda no ofrece negación plausible: es evidente que `MiBoveda.vault` es una bóveda cifrada. |

## Rastros que deja el sistema operativo (fuera del control de la app)

La app **jamás** escribe contenido en claro, temporales, logs ni contraseñas
a disco. Pero el SO puede hacerlo por su cuenta:

1. **Pagefile (swap)** — Windows puede paginar a `pagefile.sys` la RAM de la
   app con claves o el video que estás viendo. Mitigación parcial (admin):
   ```
   fsutil behavior set encryptpagingfile 1    # cifra el pagefile (reiniciar)
   ```
2. **Hibernación** — `hiberfil.sys` es un volcado completo de la RAM.
   Mitigación real:
   ```
   powercfg /h off        # desactiva hibernación y borra hiberfil.sys
   ```
3. **Volcados de error (WER/minidumps)** — si la app crashea con la bóveda
   abierta, el volcado puede contener claves y contenido. Se pueden
   desactivar en `Panel de control → Sistema → Inicio y recuperación` y en
   la telemetría de Windows Error Reporting.
4. **Cachés y copias previas a la importación** — los archivos ORIGINALES
   estuvieron en claro en tu disco antes de importarlos: la caché de
   miniaturas de Windows (`thumbcache_*.db`), "archivos recientes",
   índices de búsqueda y el propio contenido borrado pueden conservar
   rastros de ellos. Importar no borra ese pasado.
5. **Borrado en SSD** — borrar los originales (o blobs) no destruye los
   datos físicamente: el wear-leveling del SSD conserva copias inaccesibles
   para la app. Ningún "borrado seguro" a nivel de aplicación es fiable en
   SSD.
6. **Memoria de Python/Qt** — los `str` de Python son inmutables y Qt hace
   copias internas (el campo de contraseña, texturas del reproductor, la
   caché de píxeles). El *zeroize* que hace la app es best-effort: reduce la
   ventana, no la garantiza.
7. **Carpetas sincronizadas** — si la bóveda vive en OneDrive/Dropbox, la
   nube ve blobs cifrados (bien) pero también cuándo y cuánto añades
   (patrones de actividad), y guarda historiales de versiones. La app avisa
   al crear una bóveda ahí.
8. **Bóvedas recientes (opcional)** — por comodidad, la pantalla de
   apertura puede recordar las últimas RUTAS de bóveda en el registro de
   Windows (`HKCU\Software\VaultJam`). No contienen contraseñas ni contenido,
   pero sí revelan que existen bóvedas y dónde (incluso si están en un USB
   desconectado). Es configurable con la casilla «Recordar las últimas
   bóvedas abiertas»: al desactivarla se borra la lista y no se guarda nada
   más; el botón «Olvidar» borra la lista sin desactivar la función. De
   todos modos, una carpeta `.vault` en el disco ya es visible por sí
   misma: la bóveda no ofrece negación plausible.

**La mitigación de fondo para 1–5 es cifrado de disco completo (BitLocker).**
Con BitLocker activo, pagefile, hiberfil, volcados y restos de originales
quedan cifrados en reposo. Esta app está pensada para *complementar*
BitLocker (protección con la sesión iniciada y granularidad por archivo),
no para sustituirlo.

## Resumen en una frase

Protege muy bien tus fotos y videos **en reposo** frente a quien tenga tu
disco pero no tu contraseña; no puede protegerte de un Windows comprometido,
de lo que el SO escriba por su cuenta (sin BitLocker), ni de una contraseña
débil.
