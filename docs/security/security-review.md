# Revisión adversarial y gates de seguridad

Fecha: 2026-09-05  
Alcance revisado: diseño documental V1, no implementación  
Veredicto: **aprobación condicional para implementar; no aprobado para producción**.

## Hallazgos adversariales

### Critical

Ninguno en la especificación tras introducir separación cuenta/vault, slots redundantes, AAD contextual y recuperación sin escrow. Este resultado no implica que una implementación todavía inexistente carezca de Critical.

### High abiertos

**H-01 — Consistencia frente a servidor malicioso es parcial.** El DAG firmado impide falsificación, pero no que el servidor mantenga forks permanentes o entregue un rollback completo a un dispositivo nuevo. El producto NO DEBE prometer rollback prevention global. Gate: checkpoint transferido desde dispositivo/backup confiable, pruebas de fork y copy explícito; antes de una promesa más fuerte se necesita transparency log/gossip o servicio testigo.

**H-02 — No hay test vectors ni biblioteca común validados.** Elegir primitivas no demuestra interoperabilidad Rust/WASM/iOS. Gate: suite dependency seleccionada y auditada, vectores positivos/negativos versionados y ejecutados en todas las plataformas antes de persistir datos reales.

**H-03 — El content script termina insertando un secreto en DOM hostil.** XSS u otra extensión puede leerlo. Esto es inherente a autofill, pero autofill automático amplía daño. Gate: default a selección/gesto, exact-origin matching, credencial única por solicitud, aislamiento de mensajes y E2E hostiles. La UI debe decir que rellenar comparte el secreto con ese sitio.

**H-04 — La ceremonia de dispositivo depende de componentes aún no congelados.** Wordlist/SAS, schemas y validación de firma no tienen vector. Gate: fijar wordlist licenciada, CBOR bytes y pruebas MITM/replay/expiry antes de habilitar alta remota.

### Medium abiertos

**M-01 — Argon2id 64 MiB puede exceder límites de extensiones móviles.** La especificación evita degradación y mueve unlock al host, pero falta benchmark. Gate: medir dispositivos soportados, timeout/cancelación y memoria; cualquier perfil alternativo requiere nueva suite/revisión.

**M-02 — Borrado de memoria en JS/WASM es best effort.** Copias GC/JIT pueden persistir. Gate: core en memoria lineal controlada cuando sea viable, API que no exponga claves, zeroize probado donde la plataforma lo permita, TTL corto y documentación honesta.

**M-03 — Metadatos y tamaños filtran actividad.** Gate: inventario exacto de campos server-side, padding/batching evaluado, logging allowlist y privacy review. No llamar al sistema “metadata-zero-knowledge”.

**M-04 — Retención de backups limita el efecto de rotación.** Un backup antiguo + clave antigua conserva datos históricos. Gate: política de expiración/borrado verificable, inventario de copias y advertencia en incident response.

**M-05 — Disponibilidad/recovery de cuenta puede convertirse en bypass UX.** Soporte no puede abrir vault, pero una pantalla ambigua induciría falsas expectativas o phishing. Gate: pruebas de copy y flujo que nunca solicita recovery/master key al servidor.

### Low / hardening

- Instrumentar detección de `(key_id, nonce)` repetido en tests y, cuando no filtre más metadata, constraint local.
- Aplicar padding por buckets a objetos tras medir coste.
- Evaluar clipboard con auto-clear y warning; no prometer borrado en gestores de portapapeles externos.
- Mantener allowlist de algoritmos COSE/WebAuthn; no basarse únicamente en `signCount`.

## Gate obligatorio para todo cambio criptográfico

Un cambio en cifrado, KDF, serialización, recovery, WebAuthn/PRF, desbloqueo, sync authenticity o almacenamiento de secretos NO puede mergearse hasta adjuntar:

- descripción del cambio, activo/amenaza e invariantes afectadas;
- diff de `cryptographic-protocol.md`, `threat-model.md` y recovery si aplica;
- revisión Security independiente del autor y revisión adversarial QA;
- algoritmo de biblioteca mantenida, licencia compatible, versión fijada y análisis de advisories/SBOM;
- vectores actualizados positivos, negativos y cross-platform;
- unit/property/fuzz/integration tests relevantes;
- migration plan N-1→N, downgrade/rollback behavior y recovery desde interrupción;
- benchmarks de KDF/memoria/plataformas cuando aplique;
- evidencia de que logs, crash dumps, analytics y fixtures no contienen secretos;
- plan de rollout/rollback que no reactive criptografía retirada.

Fallo en tag/firma, vector divergente, downgrade silencioso, nonce reuse, plaintext persistente o camino de recuperación no probado bloquea merge/release. Un bug funcional no justifica desactivar una validación de seguridad.

## Gates de implementación

### Antes de primer dato persistido

- Schemas CBOR y límites congelados; decoder fuzzed.
- Biblioteca XChaCha/Argon2/Ed25519/X25519 seleccionada por plataforma y pin reproducible.
- Vectores comunes con CI; CSPRNG y zeroization wrappers revisados.
- Ningún secreto en errores/logging; test canary recorre logs/telemetría.

### Antes de sync multi-dispositivo

- Firmas, device sequence, idempotencia, DAG/multi-head y tombstones testeados.
- Simulaciones de servidor que replay/rollback/fork/omite/reordena.
- Checkpoint local sellado y transferencia confiable; copy reconoce límite del fresh device.
- Revocación no se presenta como borrado remoto de claves ya conocidas.

### Antes de WebAuthn/YubiKey/PRF

- Validación server-side completa de ceremonia y challenge de uso único.
- Feature detection real: `enabled` en registro y `results` de 32 bytes en assertion.
- Output PRF queda local; test impide `toJSON()`/logging accidental.
- Segundo método de vault confirmado; dos llaves cuando hardware sea esencial.
- Matriz probada navegador/OS/autenticador; degradación cerrada y comprensible.

### Antes de release candidate

- Threat model revisado contra implementación/DFD; pentest del boundary content script.
- Dependencias/SAST/secrets scan/fuzz corpus limpios y reproducibles.
- Recovery drill y rotación interrumpida pasan en todas las plataformas.
- Import/export no deja plaintext temporal; backup/restore conserva versión/checkpoint.
- Todos los High cerrados o aceptación formal con owner/fecha; ningún Critical abierto.

## Casos que intentan romper el diseño

1. Cambiar `object_id`, `object_type`, epoch o key ID manteniendo ciphertext: AEAD debe fallar.
2. Copiar un slot entre cuentas/vaults o sustituir recovery por password: AAD/HKDF deben fallar.
3. Reutilizar un nonce con otro header: instrumentation detecta; mutation no descifra.
4. Entregar KDF de 1 TiB/1000 iteraciones: parser rechaza antes de reservar.
5. Omitir PRF pese a solicitarlo o devolver tamaño incorrecto: no se crea slot.
6. Servidor sustituye X25519 key en alta: SAS difiere; no hay envelope.
7. Servidor sirve head antiguo, omite rama o repite sequence: checkpoint/DAG alerta y bloquea escritura.
8. Content script cambia tab/frame/origin entre petición y fill: broker revalida inmediatamente y cancela.
9. Dispositivo revocado firma op nueva válida: device-list-version la rechaza; si hay exfiltración, se rota VRK.
10. Rotación cae después de envolver solo parte: lector usa commit atómico anterior; no mezcla epochs.

## Fuentes normativas consultadas

- [RFC 9106 — Argon2](https://datatracker.ietf.org/doc/html/rfc9106)
- [libsodium — XChaCha20-Poly1305](https://doc.libsodium.org/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction)
- [RFC 5869 — HKDF](https://datatracker.ietf.org/doc/html/rfc5869)
- [RFC 8949 — CBOR](https://www.rfc-editor.org/rfc/rfc8949.html)
- [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)
- [Yubico — WebAuthn PRF developer guide](https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/Developers_Guide_to_PRF.html)
- [NIST SP 800-63B rev. 4](https://pages.nist.gov/800-63-4/sp800-63b.html)

## Revisión requerida al existir código

Esta revisión solo evalúa el diseño. Reabrirla al seleccionar dependencias, generar schemas/vectores, implementar cada plataforma y antes de RC. Security debe trazar cada invariante a tests y líneas de implementación; QA debe repetir los diez ataques anteriores sin confiar en mocks del happy path.

