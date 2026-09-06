# Recuperación, rotación y pérdida de dispositivos

Estado: política normativa V1  
Última revisión: 2026-09-05

## Dos recuperaciones diferentes

1. **Cuenta:** recuperar capacidad de autenticarse ante el servicio y descargar ciphertext. No abre el vault.
2. **Vault:** obtener la VRK mediante contraseña maestra, recovery key, un dispositivo confiable o un slot WebAuthn PRF. No crea por sí sola una sesión de servicio.

La UI siempre explica cuál se está recuperando. Email/support/billing proof puede ayudar con la cuenta, pero **nunca** genera, custodia ni sustituye una clave capaz de descifrar el vault. El servidor no guarda escrow de VRK. NIST trata account recovery como un evento excepcional, recomienda recovery codes offline y exige notificación; véase [SP 800-63B rev. 4, Authenticator Event Management](https://pages.nist.gov/800-63-4/sp800-63b/events/).

## Configuración mínima antes de usar el vault

- Crear recovery key criptográfica de 256 bits y mostrarla una sola vez, imprimible/descargable sin telemetría.
- Exigir confirmación introduciendo grupos seleccionados o escaneando de vuelta; “la vi” no basta.
- Mantener al menos dos vías independientes de vault: contraseña + recovery key es el baseline. Si se deshabilita contraseña, exigir recovery key confirmada y dos dispositivos/PRF independientes.
- Recomendar dos passkeys de cuenta; para YubiKey, registrar dos llaves físicas guardadas separadamente.
- Ejecutar “recovery check” periódico local que solo intenta descifrar el slot y no sube la clave.

No se permiten preguntas de seguridad, recovery key por email, copia de VRK para soporte ni reset administrativo del vault.

## Flujos

### Contraseña olvidada

El usuario primero recupera/autentica la cuenta con WebAuthn u otro autenticador registrado. Abre VRK mediante recovery key, dispositivo confiable o PRF. Crea nueva contraseña: nuevo salt Argon2id, slot y nonce; verifica descifrado de una muestra y publica el reemplazo atómicamente. Revoca el slot anterior. No se recifran los objetos.

Si solo posee la contraseña pero perdió la cuenta, el cliente puede abrir un backup local/cifrado offline; para sincronizar debe completar account recovery por separado.

### Segundo dispositivo disponible

Usar la ceremonia de alta con X25519, firma y comparación SAS definida en `cryptographic-protocol.md`. El nuevo dispositivo no recibe un export plaintext. Tras alta, sincroniza, verifica checkpoint/heads y crea su slot local. Una solicitud no confirmada nunca activa el dispositivo.

### Recovery key

1. Autenticar cuenta y descargar el envelope; aplicar rate limiting aunque la clave tenga alta entropía.
2. Decodificar Base32/checksum localmente y derivar KEK local; no enviar el secreto.
3. Descifrar VRK, verificar al menos un objeto/checkpoint y mostrar divergencias/rollback antes de escribir.
4. Registrar nuevos factores.
5. Rotar inmediatamente la recovery key: secreto, slot y checksum nuevos; invalidar el slot previo; notificar por canales de cuenta.

El uso de recovery key se considera step-up y evento auditable sin secreto, IP completa ni ciphertext.

### YubiKey perdida

- Revocar su credencial WebAuthn de cuenta y, por separado, su slot PRF.
- Autenticar con segunda YubiKey/passkey y abrir con contraseña, recovery key, dispositivo o segundo PRF.
- Registrar reemplazo y comprobarlo antes de cerrar sesión.
- Si la llave pudo usarse junto con PIN robado y contenía PRF, tratar VRK como posiblemente expuesta y ejecutar rotación completa.

La presencia de una segunda YubiKey se comprueba con una ceremonia real, no por modelo/nombre. La extensión PRF puede no estar disponible y debe detectarse; [WebAuthn L3](https://www.w3.org/TR/webauthn-3/#prf-extension) especifica que extensiones opcionales pueden ignorarse.

### Dispositivo perdido o robado

Desde otro dispositivo: revocar sesiones, passkeys/credenciales locales asociadas y device ID; incrementar device-list-version; invalidar solicitudes; notificar. Revocación impide sync futuro, pero no borra claves ya copiadas. Si el dispositivo estaba desbloqueado, su almacenamiento pudo extraerse o no puede confirmarse el bloqueo, rotar VRK/epoch y todos los slots.

### Todos los dispositivos perdidos

Se necesitan **ambos**: una vía de cuenta para descargar y la recovery key/otro factor de vault para descifrar. Si hay backup cifrado, recovery key/contraseña puede abrirlo offline. Tras recuperar, registrar dispositivos/passkeys nuevos, rotar recovery key, revocar los anteriores y crear/exportar checkpoint actualizado.

### Pérdida de todos los factores de vault

El contenido es irrecuperable por diseño. Soporte puede borrar la cuenta o ayudar a recuperar autenticación según política, pero no descifrar ni “resetear” la contraseña conservando datos. Este hecho debe mostrarse durante onboarding y al retirar el último factor redundante.

## Rotación segura

| Evento | Acción mínima |
|---|---|
| Cambio rutinario de contraseña | Rewrap de VRK solo para slot de contraseña |
| Recovery key mostrada/expuesta | Nueva recovery key y slot; revocar anterior |
| YubiKey perdida, no PRF o VRK no expuesta | Revocar auth + slot; no requiere recifrar objetos |
| Dispositivo desbloqueado comprometido / VRK expuesta | Nueva VRK y epoch; rewrap de todos los DEK; recrear slots |
| Algoritmo/suite retirado | Migración versionada de envelopes/objetos con backup y rollback controlado |

Toda rotación es transaccional: preparar nuevo estado, verificarlo con un segundo lector/vector, publicar commit/checkpoint, y solo entonces retirar el antiguo. Interrupción conserva al menos un conjunto completo legible. La retención de backups antiguos debe estar documentada porque conserva exposición a claves antiguas.

## Revocación y notificaciones

Eventos: alta/revocación de autenticador o dispositivo, recovery usado/rotado, contraseña cambiada, export, epoch rotado, downgrade/rollback detectado. La notificación incluye momento aproximado, dispositivo y acción de contención; nunca secreto, título/URL de credencial, token completo o ciphertext. Cambios críticos tienen una ventana de enfriamiento solo si no bloquea contención de un ataque activo.

## Ensayos de recuperación para release

- contraseña olvidada → recovery key → contraseña nueva → objetos intactos;
- dispositivo A aprueba B con SAS; sustitución de public key falla;
- segunda YubiKey funciona; PRF ausente degrada a factor alternativo sin crear slot roto;
- dispositivo revocado no publica operaciones; conflicto histórico no se pierde;
- backup viejo provoca alerta de epoch/checkpoint y no sobrescribe estado nuevo;
- corte de energía/red en cada paso de rotación deja conjunto anterior o nuevo completo;
- pérdida total muestra mensaje irreversible y no ofrece falsa recuperación de soporte.

Los simulacros se ejecutan con fixtures sin secretos reales y sus resultados forman parte del release gate.

