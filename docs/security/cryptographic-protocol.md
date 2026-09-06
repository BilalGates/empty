# Protocolo criptográfico de Space

Estado: especificación V1 para implementación; no es aprobación de producción  
Identificador de suite: `space.vault/1`  
Última revisión: 2026-09-05

Los términos DEBE/NO DEBE/DEBERÍA son normativos. Cualquier divergencia entre plataformas es un cambio de protocolo.

## Suite V1

| Función | Algoritmo/parámetros |
|---|---|
| Entropía | CSPRNG del sistema |
| KDF de contraseña | Argon2id v=0x13, m=65,536 KiB, t=3, p=4, salt=16 bytes, output=32 bytes |
| Expansión/separación | HKDF-SHA-256, output=32 bytes |
| AEAD | XChaCha20-Poly1305-IETF, key=32, nonce=24, tag=16 bytes |
| Hash | SHA-256 |
| Checkpoint MAC | HMAC-SHA-256 |
| Firma de dispositivo | Ed25519 |
| Alta de dispositivo | X25519 + HKDF-SHA-256 + XChaCha20-Poly1305-IETF |
| Serialización firmada/AAD | CBOR determinista según RFC 8949 §4.2.1; enteros como keys; sin floats/tags/indefinite lengths |

Argon2id usa la segunda opción uniforme de [RFC 9106 §4](https://datatracker.ietf.org/doc/html/rfc9106#section-4), diseñada para entornos con menos memoria (64 MiB, tres pasadas, cuatro lanes); supera el mínimo operativo de [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html). XChaCha permite nonces aleatorios de 192 bits y es la opción recomendada por [libsodium](https://doc.libsodium.org/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction) cuando la interoperabilidad de librerías no manda. Toda plataforma DEBE usar una implementación auditada y vectores comunes; si iOS/WASM no puede ofrecer la misma construcción, el proyecto DEBE cambiar de suite versionada (candidato: AES-256-GCM con gestión formal de nonces), no implementar XChaCha manualmente. HKDF se usa solo para separación de dominios conforme a [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869).

El host app realiza Argon2; una extensión iOS de AutoFill con memoria restringida usa una clave local ya desbloqueada/protegida por Keychain o abre la app host. NO DEBE reducir parámetros en silencio. Los parámetros se almacenan por slot para migración, pero V1 rechaza `m < 65536`, `t < 3`, `p < 1`, salt distinto de 16 o output distinto de 32; también impone máximos razonables antes de asignar memoria (`m <= 1 GiB`, `t <= 10`, `p <= 16`) para evitar DoS de parser. Un futuro perfil calibrado requiere nueva revisión y nunca baja el coste efectivo sin migración explícita.

## Jerarquía de claves

```text
factor de desbloqueo ──KDF/HKDF──> KEK de slot ──AEAD──> VRK aleatoria (32 B)
                                                        │
                                                        ├─HKDF─> Vault Wrap Key (VWK)
                                                        │           └─AEAD─> DEK aleatoria por objeto
                                                        │                       └─AEAD─> payload
                                                        └─HKDF─> Checkpoint MAC Key
```

- VRK: 32 bytes aleatorios por vault. Nunca deriva de la contraseña ni sale en claro del proceso confiable.
- KEK: independiente por slot de desbloqueo. Un slot envuelve la misma VRK.
- VWK: `HKDF-SHA-256(IKM=VRK, salt=vault_id, info="space/vwk/v1", L=32)`.
- Checkpoint key: `HKDF-SHA-256(IKM=VRK, salt=vault_id, info="space/checkpoint/v1", L=32)`.
- DEK: 32 bytes aleatorios por objeto/versión; cifra únicamente ese payload y queda envuelta por VWK.

No se reutiliza una clave para dos propósitos. Los textos de `info` son bytes ASCII exactos mostrados. `vault_id`, `slot_id`, `object_id`, `key_id`, `device_id` y `op_id` son 16 bytes aleatorios (la representación textual nunca entra en cripto).

## Codificación y framing

Cada artefacto es `magic(4) || protocol_version(u16be) || kind(u8) || cbor_length(u32be) || deterministic_cbor`. `magic = 53 50 43 45` (`SPCE`). Límites V1 antes de parsear: artefacto 16 MiB; header/AAD 16 KiB; nesting 16; mapa 64 pares; string 1 MiB. Se rechazan trailing bytes, duplicate keys, valores desconocidos críticos y codificación CBOR no determinista. RFC 8949 distingue explícitamente well-formed, valid y expected input y define la codificación determinista: [RFC 8949 §§4.2, 5](https://www.rfc-editor.org/rfc/rfc8949.html).

Los mapas siguientes usan nombres legibles en esta especificación; el schema y los vectores fijarán keys enteras. `aad_bytes` es la codificación CBOR determinista exacta del mapa `aad`, no una reconstrucción desde objetos de lenguaje.

### Objeto cifrado V1

```text
aad = {
  suite: "space.vault/1", kind: "vault-object", vault_id, object_id,
  object_type, object_version, epoch, key_id, created_by_device
}
record = {
  aad,
  wrapped_dek: { nonce: random(24), ciphertext: AEAD_Encrypt(VWK, nonce, DEK, aad_bytes || "\0dek") },
  payload:     { nonce: random(24), ciphertext: AEAD_Encrypt(DEK, nonce, payload_cbor, aad_bytes || "\0payload") }
}
```

`object_type` incluye `password`, `passkey`, `totp`, `secure-item` o `tombstone`. Metadata sensible (título, URL, username, grupo y timestamps semánticos) vive en `payload`; el servidor solo recibe routing/revision IDs, longitudes y ciphertext. Actualizar un objeto genera DEK y nonces nuevos. El descifrado valida ambos tags antes de parsear payload.

### Slot de contraseña

La contraseña se normaliza uniformemente con Unicode NFC y después se codifica como UTF-8, sin trim ni case-fold. Toda plataforma DEBE aplicar exactamente esa transformación y conservar vectores con formas compuesta y descompuesta. Se rechaza UTF-8 inválido; se acepta 1..1024 bytes después de normalizar.

```text
argon = Argon2id(password_utf8, salt16, m=65536 KiB, t=3, p=4, out=32)
KEK = HKDF-SHA-256(IKM=argon, salt=vault_id,
                  info="space/password-kek/v1" || slot_id, L=32)
aad = { suite, kind:"key-slot", slot_type:"password", vault_id, slot_id,
        epoch, kdf:{name:"argon2id", version:19, m:65536, t:3, p:4, salt:salt16} }
wrapped_vrk = AEAD_Encrypt(KEK, random_nonce24, VRK, deterministic_cbor(aad))
```

Cambiar contraseña crea salt, KEK y nonce nuevos y reemplaza atómicamente solo este slot; no recifra objetos. Tras éxito se elimina el slot anterior de estado activo, conservándolo únicamente en backup cifrado sujeto a la política de retención.

### Slot de recovery key

`recovery_secret=random(32)`. Se muestra una vez como Base32 sin padding, grupos de cuatro, más checksum de cuatro caracteres derivado de los primeros 20 bits de `SHA-256("space/recovery-check/v1" || recovery_secret)`. El checksum detecta errores, no aporta entropía.

`KEK = HKDF-SHA-256(IKM=recovery_secret, salt=vault_id, info="space/recovery-kek/v1" || slot_id, L=32)`; el envelope usa la misma forma que el slot de contraseña con `slot_type="recovery"`. El servidor guarda ciphertext y un `recovery_key_id`, nunca el secreto ni un verificador de baja entropía. La clave tiene 256 bits y no necesita Argon2.

### Slot local/biométrico

Un dispositivo genera `device_unlock_key` de 32 bytes con CSPRNG, la guarda no exportable cuando la plataforma lo permita y condicionada a desbloqueo/presencia del usuario, y envuelve la VRK en un slot **solo local**. Face ID/Touch ID/Windows Hello autoriza el uso de esa clave: no deriva ni sustituye la VRK. Invalidar biometría/passcode debe hacer fallar de forma cerrada y volver a contraseña/recovery. Nunca se sincroniza `device_unlock_key`.

### WebAuthn, YubiKey y PRF

Para cuenta, WebAuthn usa challenge aleatorio de al menos 32 bytes, uso único, ligado a ceremonia/cuenta/sesión, expiración ≤5 min, verificación estricta de RP ID, origin, type, challenge, flags UP y UV cuando se solicite, algoritmo permitido y credential ID. Se prefiere passkey/WebAuthn; TOTP/SMS no es sustituto equivalente resistente a phishing. Attestation `none` por defecto para privacidad. Revocar una credencial de cuenta no revoca implícitamente un slot PRF; ambas operaciones deben coordinarse.

PRF es opcional y solo se habilita si registro devuelve `clientExtensionResults.prf.enabled === true` y una aserción real devuelve exactamente 32 bytes. Las extensiones WebAuthn son opcionales y pueden ignorarse; la especificación define PRF precisamente para derivar material simétrico, pero exige manejar su ausencia: [WebAuthn L3 §10.1.4](https://www.w3.org/TR/webauthn-3/#prf-extension). En CTAP2, PRF se apoya habitualmente en `hmac-secret`; no se asume soporte por “ser YubiKey” ([guía oficial de Yubico](https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/Developers_Guide_to_PRF.html)).

Para cada credencial: `prf_input=random(32)` público y estable; `prf_output=WebAuthnPRF(credential, prf_input)`; `KEK=HKDF-SHA-256(IKM=prf_output, salt=vault_id, info="space/webauthn-prf-kek/v1" || slot_id || credential_id, L=32)`. El resultado PRF NO DEBE incluirse en JSON enviado al servidor, logs ni telemetría. El slot envuelve VRK con AAD que liga credential ID y PRF input. Un slot PRF requiere, como mínimo, recovery key confirmada o segundo slot independiente; una YubiKey externa nunca es la única forma multiplataforma de abrir el vault.

## Alta y claves de dispositivo

Cada instalación genera pares Ed25519 (firma de operaciones) y X25519 (recepción de VRK), protegidos localmente. Para aprobar un dispositivo B:

1. B autentica la cuenta y publica solicitud `{request_id, vault_id, B_device_id, B_x25519_pub, B_sign_pub, expires_at}`.
2. A y B muestran un SAS de seis palabras obtenido de los primeros 66 bits de `SHA-256("space/device-sas/v1" || deterministic_cbor(request))`, usando una wordlist normativa de 2048 palabras. El usuario DEBE comparar ambos canales.
3. Tras confirmar, A crea X25519 efímero, calcula shared secret con `B_x25519_pub`, deriva `KEK=HKDF(shared, salt=vault_id||request_id, info="space/device-transfer/v1"||A_device_id||B_device_id, 32)`, envuelve VRK con XChaCha y firma todo el envelope con Ed25519 de A.
4. B verifica request, expiración, SAS, firma de A y AEAD, rechaza explícitamente un shared secret X25519 all-zero, crea su slot local y borra el material efímero.

El servidor no puede sustituir la clave sin provocar SAS distinto. No hay aprobación ciega/push. Solicitudes expiran en 10 minutos y son de un solo uso. Una wordlist concreta y vectores son requisito antes de implementar esta ceremonia.

## Sync, replay, rollback y conflicto

Cada operación contiene un header determinista `{suite,vault_id,epoch,op_id,device_id,device_seq,parent_heads[],object_id,object_version,ciphertext_hash}` y `signature=Ed25519(header_cbor)`. `device_seq` crece estrictamente; `op_id` es único; parents forman un DAG. El servidor aplica idempotencia y no puede crear operaciones válidas. El cliente rechaza firma, dispositivo/epoch, secuencia o hash inválidos y conserva todas las heads concurrentes: los secretos en conflicto no se sobrescriben por timestamp.

Tras sync, el cliente sella localmente `{vault_id,epoch,heads,max_device_seq}` autenticado con HMAC-SHA-256 bajo Checkpoint MAC Key y, donde exista, con protección anti-rollback del OS. Un estado que no descienda de ese checkpoint bloquea escritura y exige resolución. Esto detecta replay/rollback frente a clientes con estado previo; no resuelve un servidor que bifurca para siempre ni un dispositivo nuevo que solo confía en el servidor. Transferir un checkpoint desde dispositivo confiable o backup es parte de alta/recovery. No se afirmará transparencia global en V1.

Revocar dispositivo incrementa una `device-list-version` firmada dentro del DAG. Operaciones nuevas del revocado se rechazan; las previas siguen siendo historia válida. Revocación no borra una VRK que el dispositivo ya conoció: ante posible extracción, se rota VRK.

## Rotaciones y migraciones

- Contraseña/factor perdido sin sospecha de extracción: rewrap de VRK y eliminación/revocación del slot.
- VRK posiblemente extraída: generar VRK/epoch nuevos, derivar VWK nueva, reenvolver cada DEK tras autenticar su objeto, recrear slots y publicar checkpoint atómico. El contenido histórico accesible con la VRK antigua no recupera confidencialidad retroactiva.
- Suite/formato nuevo: lector puede soportar N y N-1; escritor solo la suite activa. La migración es resumible, autenticada, preserva backup cifrado y tiene test vector cross-platform. Nunca se interpreta un campo desconocido crítico.

## Gestión de secretos y errores

Las claves viven el mínimo tiempo, no se convierten a strings, no entran en crash reports/logs/analytics/clipboard salvo acción explícita. Buffers se bloquean/borran si la biblioteca lo permite; copias GC son riesgo documentado. Descifrado devuelve un único error externo `INVALID_ENVELOPE`; métricas no distinguen contraseña errónea de tag corrupto. Comparaciones de tags/checksums/IDs sensibles usan APIs constant-time. Backups incluyen solo ciphertext y metadatos necesarios.

## Vectores y conformidad obligatorios

Antes de que V1 sea implementable se deben versionar vectores positivos y negativos para Argon2id, HKDF, cada AAD/envelope, recovery encoding, PRF derivation (inyectando output), device transfer, firma/checkpoint y CBOR determinista. Se ejecutan idénticos en Rust/WASM, backend test harness e iOS. Además: property tests de round-trip/non-malleability, mutation tests por byte, fuzzing del decoder, prueba de nonce collision instrumentation y límites de recursos.
