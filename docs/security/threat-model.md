# Modelo de amenazas de Space

Estado: diseño normativo previo a V1  
Última revisión: 2026-09-05  
Propietario: Security; todo cambio criptográfico exige el gate de `security-review.md`.

## Objetivo y promesa

Space protege la confidencialidad e integridad de un vault frente al robo de la base de datos, un API comprometido y un administrador malicioso. El servidor sincroniza ciphertext y metadatos mínimos: no recibe la contraseña maestra, la Vault Root Key (VRK), claves de datos ni secretos descifrados.

“Zero knowledge” no significa invisibilidad total: el servicio conoce identificadores de cuenta/dispositivo, tamaños aproximados, tiempos, IP y patrón de sincronización. Una copia del servidor permite probar contraseñas maestras **offline** contra el slot de contraseña; Argon2id aumenta el coste, pero no convierte una contraseña débil en una clave fuerte.

La autenticación de cuenta y el desbloqueo del vault son límites distintos. Controlar una sesión del servicio permite descargar, ocultar, repetir o borrar ciphertext, pero no descifrarlo sin un factor de vault. Desbloquear el vault no otorga por sí solo una sesión de servidor.

## Activos, límites y supuestos

Activos principales: credenciales, TOTP, notas y recovery codes; VRK/DEK/KEK; recovery key; claves privadas de dispositivo; sesiones; historial cifrado y disponibilidad.

Límites de confianza:

1. página web hostil ↔ content script mínimamente privilegiado;
2. content script ↔ contexto confiable de la extensión;
3. UI/extensión/app ↔ core criptográfico y almacenamiento local;
4. cliente ↔ API/red ↔ base de datos/operador;
5. app ↔ Keychain/Secure Enclave/biometría; navegador ↔ WebAuthn/autenticador.

Supuestos: TLS y las primitivas/librerías elegidas funcionan según especificación; el dispositivo está limpio en el momento de desbloquear; el usuario compara el código de seguridad al aprobar un dispositivo nuevo; al menos un factor de recuperación permanece secreto. Relojes, `signCount` de WebAuthn y orden del servidor no son fuentes únicas de verdad.

## Adversarios y controles

| Amenaza obligatoria | Capacidad | Control/detección | Riesgo residual / resultado |
|---|---|---|---|
| Robo completo de DB/backup | Lee slots, ciphertext y metadatos | AEAD; VRK aleatoria; Argon2id; recovery key de 256 bits | Adivinación offline de contraseña; tráfico/tamaños visibles |
| API comprometido | Lee/modifica/responde selectivamente | Firmas de dispositivo, AAD, revisiones y checkpoints locales | Puede denegar servicio, suprimir cambios o bifurcar un cliente nuevo |
| Administrador malicioso | Igual que API + backups | Ninguna clave de vault en servidor; export cifrado verificable | Disponibilidad y metadatos no están protegidos; rollback global no es totalmente detectable por un dispositivo sin checkpoint confiable |
| Robo de ordenador bloqueado | Copia disco/perfil | Slot local protegido por OS; vault bloqueado; TTL; no persistir plaintext | Malware o sesión ya desbloqueada puede exfiltrar secretos |
| Robo de iPhone bloqueado | Copia/usa dispositivo | Keychain con clase accesible solo desbloqueado y control de presencia; bloqueo de app; revocación | Código del dispositivo comprometido o app ya desbloqueada reduce protección |
| Extensión maliciosa coexistente | Lee/modifica páginas, observa formularios | No entregar vault completo al content script; gesto/selección; matching de origen; CSP y permisos mínimos | Puede leer un secreto rellenado en una página que también controla; no es posible impedirlo una vez insertado en DOM |
| XSS en página visitada | Control del DOM/origen | No exponer API de vault a `window`; mensaje con canal/op/origen; rellenar solo credencial seleccionada | Tras rellenar, el XSS del mismo origen puede leer/capturar el valor |
| Content-script comprometido | Solicita fills/copias abusivas | Broker confiable valida pestaña, frame, origen, operación, estado y autorización; respuesta de uso único | Si la página/CS obtiene autorización legítima, puede capturar esa credencial; no obtiene otras |
| Malware local | Keylogging, memoria, UI injection | Mitigación parcial: bloqueo, OS keystore, borrado best-effort, actualizaciones | **Fuera de garantía** si ejecuta con privilegios del usuario durante desbloqueo |
| Pérdida de contraseña maestra | Ya no deriva Password KEK | Recovery key, dispositivo ya confiable o slot PRF; luego rewrap | Sin ningún factor, pérdida criptográfica permanente |
| Pérdida de YubiKey | Pierde auth/PRF | Segunda passkey/YubiKey, recovery key y dispositivo confiable; revocar credential/slot | Si era el único factor restante, pérdida permanente; la UI debe impedir crear ese estado |
| Pérdida simultánea de dispositivos | Sin claves locales | Recovery key offline + recuperación separada de cuenta | Sin recovery key/slot alternativo, pérdida permanente |
| Replay | Repite auth, commits o envelopes | Challenge WebAuthn único y expirante; `opId`, `deviceSeq`, firma, epoch y deduplicación | Un servidor puede re-presentar historia válida; checkpoint detecta solo si el cliente conserva uno |
| Rollback del vault | Sirve estado antiguo íntegro | Checkpoint sellado local; epoch/revisión; hash DAG; alerta y bloqueo de escritura | Fresh install recuperado solo desde servidor no detecta rollback completo |
| Conflicto malicioso de sync | Oculta/reordena heads | DAG firmado; conservar multi-head; nunca last-write-wins silencioso | Servidor puede mantener vistas bifurcadas hasta que dispositivos comparen checkpoints |
| Credential stuffing | Reusa credenciales de otros servicios | Passkeys/WebAuthn por defecto, rate limiting, sesiones ligadas a dispositivo | Recovery/account fallbacks débiles pueden degradar la cuenta, pero no descifran el vault por sí solos |
| Phishing | Imita login/autofill | WebAuthn ligado a RP; origen exacto; no autofill en dominio parecido/IDN confuso | La contraseña maestra introducida en una UI falsificada o un fill confirmado en origen erróneo puede robarse |
| Session hijacking | Roba cookie/token | Token corto, rotación, `HttpOnly`/`Secure`/`SameSite`, revocación y step-up | Permite acceso a ciphertext/metadatos y DoS; si el cliente está desbloqueado, una toma local de sesión es más grave |

WebAuthn aporta resistencia al phishing mediante el vínculo con el nombre del verificador y usa challenges para frescura/replay; véanse [NIST SP 800-63B rev. 4](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/) y [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/).

## Invariantes de seguridad

- El servidor nunca recibe la contraseña maestra ni material derivado reutilizable para descifrar.
- Todo ciphertext de vault usa AEAD y AAD que liga versión, vault, objeto, clave, epoch y tipo.
- Nonce único por clave. Se genera con CSPRNG; nunca con reloj, revisión o `Math.random()`.
- El parser rechaza antes de asignar memoria estructuras no canónicas, desconocidas, duplicadas o fuera de límites.
- Un tag/firma inválido detiene el procesamiento; no hay recuperación parcial ni mensajes-oráculo diferentes.
- El content script nunca recibe índices completos, notas, TOTP seeds, DEK ni VRK.
- Copiar, revelar, exportar plaintext, cambiar factores y añadir dispositivo requieren reautenticación/step-up reciente.
- El cliente no acepta disminuir KDF, epoch o versión desde datos no confiables.
- Borrar localmente secretos incluye buffers y temporales en best effort; en runtimes con GC no se promete borrado perfecto.

## Fuera del alcance de V1

Compromiso del endpoint mientras el vault está abierto; firmware/OS/autenticador comprometido; coerción; análisis de tráfico global; disponibilidad frente al operador; prevención absoluta de screenshots/clipboard; impedir que un origen autorizado lea la credencial ya rellenada; anonimato frente al servicio; consistencia global verificable sin un canal/checkpoint independiente.

## Casos de abuso que deben probarse

Mutación de cada byte de header/AAD/ciphertext; nonce repetido; slot cruzado entre vaults; objeto sustituido por tombstone; KDF con memoria extrema; CBOR duplicado/no canónico/recursivo; commit firmado por dispositivo revocado o con secuencia repetida; challenge WebAuthn repetido; PRF solicitado pero omitido; respuesta de content script desde frame/origen distinto; IDN homógrafo; recuperación con snapshot antiguo; servidor que oculta una rama de conflicto.

