# Patrones por plataforma

## Extensión Chrome

### Popup

El popup es una herramienta contextual, no el vault completo. Ancho objetivo entre 340 y 400 CSS px, altura adaptable y scroll interno único. Su anatomía:

1. cabecera compacta con `Space`, estado de bloqueo o sync y acceso a opciones;
2. origen actual como contexto de seguridad;
3. búsqueda cuando hay varias opciones o no hay coincidencia;
4. credenciales como lista continua;
5. acción contextual principal;
6. enlace `Abrir Space` para gestión completa.

No incluye sidebar, tabs persistentes, métricas, saludo, plan de pago, actividad ni una cuadrícula de accesos rápidos.

Estados mínimos:

- bloqueado;
- desbloqueando o reautenticando;
- vault vacío;
- una coincidencia exacta;
- varias coincidencias;
- sin coincidencia;
- origen parecido o sospechoso;
- formulario no compatible;
- offline con datos locales;
- sync pendiente, fallo o conflicto;
- sesión o dispositivo revocado.

### Popup: reglas de foco

- Apertura desde icono: foco en `Desbloquear Space`, coincidencia primaria o búsqueda según estado.
- `Escape` cierra menú o diálogo antes que el popup.
- Cerrar y reabrir no debe revelar el último secreto mostrado.
- Los menús usan patrón nativo y no quedan recortados por el contenedor.
- Mensajes que provocan cierre anuncian el resultado antes o delegan feedback seguro en la página.

### Overlay en página

El affordance junto al campo debe ser pequeño, reconocible y no alterar el layout del sitio. Solo aparece en campos compatibles. La lista flotante:

- muestra origen y credenciales coincidentes;
- se posiciona sin tapar el campo activo cuando exista espacio;
- soporta teclado y mantiene foco lógico;
- usa Shadow DOM o aislamiento compatible sin romper estilos del sitio;
- no envía el vault completo al content script;
- se cierra ante navegación, cambio de origen, bloqueo o `Escape`.

Una página no puede imitar una confirmación privilegiada de Space. Las decisiones sensibles ocurren en contexto de extensión confiable.

### Guardar y actualizar

La invitación aparece después de evidencia suficiente de submit exitoso. Debe permitir revisar origen y usuario. Si la detección es incierta, se ofrece abrir Space con campos propuestos en lugar de guardar automáticamente.

## iOS

### App host

Usa NavigationStack y patrones SwiftUI estándar. En iPhone:

- pantalla raíz: título `Space`, búsqueda, lista de credenciales y acción crear;
- filtros o grupos en sheet o navegación secundaria cuando sean necesarios, no como sidebar comprimida;
- detalle mediante push;
- edición mediante sheet o push coherente, con `Cancelar` y `Guardar` en posiciones nativas;
- settings separados de la tarea principal.

List y Form son preferibles a recreaciones visuales que reduzcan accesibilidad. Los secretos no aparecen en widgets, Spotlight, notificaciones o previews de multitarea.

### Bloqueo y biometría

- Al abrir bloqueado, el sistema puede solicitar Face ID tras una acción clara o según preferencia segura.
- Cancelar deja una pantalla bloqueada útil con opciones disponibles.
- Face ID desbloquea una clave protegida por el sistema; la copia explica “Desbloquear con Face ID”, no “Entrar con Face ID”.
- Acciones sensibles pueden exigir reautenticación aunque el vault esté abierto.

### AutoFill Credential Provider

Optimiza para límites estrictos de tiempo y memoria:

1. mostrar bloqueo o identidades sugeridas;
2. autenticar con mecanismo disponible;
3. devolver la credencial seleccionada;
4. cerrar sin retener contenido sensible.

Con coincidencia única segura, la sugerencia rápida usa nombre de servicio y usuario. Con varias, abre búsqueda. Sin datos locales disponibles, explica `Abre Space para sincronizar tu vault` y ofrece la acción permitida por el sistema.

El proveedor no intenta convertirse en una versión reducida de toda la app. Edición, importación, exportación y gestión de dispositivos viven en la app host.

### Convenciones iOS

- Back, Cancel, Done, Search y menus siguen localización y ubicación del sistema.
- Swipe actions solo duplican acciones disponibles de otro modo. Eliminar siempre confirma.
- Haptics solo confirman éxito, error o una selección relevante y respetan preferencias.
- Sheets tienen detents solo cuando el contenido funciona en todos ellos; formularios críticos usan espacio suficiente.
- Se usa monospaced digit para TOTP, no fuente monoespaciada en toda la app.

## Paridad intencional

Debe ser idéntico:

- nombres de conceptos y acciones;
- matching de origen y advertencias;
- reglas de bloqueo, copia, revelado y reautenticación;
- estados de sync y conflicto;
- consecuencias de recovery y exportación.

Debe ser nativo, no idéntico visualmente:

- navegación;
- modales y sheets;
- menús, context menus y swipe actions;
- biometría;
- selector AutoFill;
- tipografía, espaciado y feedback de sistema.

