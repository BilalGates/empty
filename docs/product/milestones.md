# Alcance por milestones

## Regla de cierre

Un milestone solo se cierra cuando el flujo está implementado en las superficies indicadas, integrado, probado, accesible, documentado y sin hallazgos Critical o High abiertos. Una pantalla dibujada o un happy path aislado no cuentan como terminado.

## M0: contrato de experiencia y prototipo de riesgo

**Objetivo:** eliminar ambigüedades antes de construir.

Incluye:

- vocabulario común de cuenta, dispositivo, vault, bloqueo y recovery;
- mapa de información, flujos y estados de este directorio;
- prototipo navegable del popup y del vault iOS con estados vacío, con datos y bloqueado;
- prueba de comprensión de la separación cuenta-vault y del mensaje de pérdida total;
- validación técnica temprana de AutoFill, AuthenticationServices y límites de extensión.

Criterios verificables:

- 5 de 5 participantes distinguen “acceder” de “desbloquear” tras recorrer onboarding, sin explicación del moderador;
- 4 de 5 encuentran una credencial y describen el origen antes de rellenar en menos de 30 segundos;
- teclado y VoiceOver pueden completar los prototipos críticos;
- toda capacidad no validada se etiqueta como hipótesis, no como funcionalidad comprometida.

## M1: vault Password local

**Objetivo:** crear, consultar y mantener passwords sin sincronización.

Incluye:

- onboarding, contraseña maestra y recovery key;
- vault vacío, creación, edición, eliminación y búsqueda;
- mostrar y copiar con reautenticación según riesgo;
- generador de contraseñas;
- bloqueo manual, por inactividad y tras reinicio;
- grupos planos opcionales;
- estados de error, offline local y datos corruptos no recuperables.

No incluye: sync, importación, passkeys, TOTP operativo ni YubiKey.

Criterios verificables:

- crear, bloquear, desbloquear y recuperar conserva los datos en pruebas reproducibles;
- ningún secreto aparece en logs, accesibilidad, notificaciones o capturas de multitarea iOS;
- búsqueda devuelve resultados por título, usuario y origen, nunca por contraseña o notas sensibles indexadas fuera del vault;
- todos los controles críticos cumplen el inventario de estados de `docs/design/interaction-and-states.md`.

## M2: extensión Chrome y AutoFill Password

**Objetivo:** completar el trabajo dentro de la página sin exponer el vault completo.

Incluye:

- popup bloqueado, vacío, coincidencia única, múltiples coincidencias y sin coincidencia;
- seleccionar, rellenar, copiar, mostrar y generar;
- guardar login nuevo y actualizar contraseña;
- detección de formularios tradicionales, SPA y dinámicos;
- advertencia por origen no coincidente y homógrafo sospechoso;
- acceso al vault completo mediante una vista dedicada, no comprimida dentro del popup.

Criterios verificables:

- E2E en fixtures cubre login, signup, cambio de contraseña, SPA, iframe permitido y varias credenciales;
- el popup permite rellenar una coincidencia habitual con teclado en tres acciones o menos tras desbloquear;
- el content script recibe solo los campos requeridos para la acción actual;
- no se rellena automáticamente un origen que difiera en esquema, host efectivo o puerto relevante según la política documentada.

## M3: sync y múltiples dispositivos

**Objetivo:** mantener el vault coherente sin sobrescrituras silenciosas.

Incluye:

- estado de sync discreto y accesible;
- trabajo offline, reintentos e idempotencia;
- conflicto detectado, comparación segura y resolución explícita;
- dispositivos, revocación y sesiones;
- cambio de contraseña maestra y rewrapping.

Criterios verificables:

- pasan los escenarios PC A, PC B, borrado, edición offline concurrente, revocación y cambio de contraseña;
- un error de sync nunca bloquea lectura local de datos ya disponibles;
- la interfaz no dice “Todo guardado” hasta recibir confirmación persistente;
- un conflicto muestra qué campos difieren sin revelar contraseñas por defecto.

## M4: iPhone y AutoFill Password

**Objetivo:** ofrecer acceso nativo al mismo vault y credenciales en AuthenticationServices.

Incluye:

- app SwiftUI host, vault local, sync, Keychain y Face ID;
- extensión AutoFill Credential Provider;
- identidades para sugerencias rápidas;
- búsqueda y elección dentro del proveedor;
- bloqueo, privacidad en app switcher y reautenticación sensible.

Criterios verificables:

- AutoFill ofrece la identidad adecuada en los dominios fixture y nunca una de origen parecido;
- cancelar Face ID devuelve al estado anterior sin filtrar datos;
- Dynamic Type hasta tamaños de accesibilidad no corta secretos, acciones ni advertencias;
- la extensión funciona bajo sus límites reales de memoria y tiempo, con fallback comprensible.

## M5: importación, backup y recovery probado

**Objetivo:** entrar y salir de Space sin perder control.

Incluye:

- importación local desde Chrome/Google Password Manager y formatos priorizados;
- revisión, validación y deduplicación conservadora;
- backup cifrado versionado por defecto;
- CSV explícito con reautenticación y advertencia;
- recovery desde key o segundo dispositivo, rotación y pérdida de dispositivo.

Criterios verificables:

- el archivo de importación nunca se sube y el usuario puede verificarlo en prueba de red;
- el resumen distingue creadas, duplicadas, inválidas y omitidas, con descarga local de errores sin secretos innecesarios;
- restaurar un backup cifrado en una instalación limpia reproduce el vault esperado;
- antes de CSV, el usuario debe confirmar que el archivo será legible y no protegido por Space.

## M6: factores avanzados y tipos adicionales

**Objetivo:** ampliar capacidades sin comprometer recuperación ni compatibilidad.

Incluye, por entregas independientes:

- YubiKey FIDO2/WebAuthn como factor de cuenta;
- PRF o hmac-secret solo tras capability detection y recovery verificado;
- TOTP;
- passkeys mediante APIs oficiales disponibles;
- RecoveryCode o secure item si el modelo de uso está validado.

Criterios verificables:

- cada capacidad tiene fallback explícito por plataforma;
- ninguna YubiKey externa es el único método global de desbloqueo;
- la interfaz diferencia “no compatible”, “no configurado”, “temporalmente no disponible” y “falló”;
- una capacidad experimental no degrada el flujo Password estable.

## Fuera del alcance inicial

- vaults familiares o empresariales;
- sharing en tiempo real;
- panel administrativo de seguridad;
- jerarquías complejas de carpetas;
- personalización visual extensa;
- sincronización privada con la base interna de Apple Passwords.

