# Interacción y estados

## Principios de interacción

- Los datos ya disponibles aparecen inmediatamente. La carga secundaria no reemplaza toda la pantalla.
- Skeleton solo donde se espera contenido estructurado y durante más de 300 ms. Para acciones breves, el botón conserva etiqueta y muestra progreso sin cambiar de tamaño.
- Las operaciones optimistas se reservan a cambios reversibles. Guardar secretos, sync, revocación y exportación muestran pendiente hasta confirmación.
- Deshacer se ofrece para cambios locales reversibles. Eliminar un secreto requiere confirmación y no depende solo de un toast fugaz.

## Estado vacío

Composición:

- nombre de la superficie;
- una frase de máximo 90 caracteres;
- acción primaria `Crear credencial`;
- `Importar credenciales` como secundaria solo cuando esté disponible;
- sin ilustración obligatoria, estadísticas, tutorial multipaso ni tarjetas de ejemplo.

Texto recomendado: `Tu vault está vacío. Crea una credencial para empezar.`

En búsqueda sin resultados, no se reutiliza el vacío inicial: `No hay resultados para “consulta”`. Acciones: `Borrar búsqueda` y, si procede, `Crear credencial`.

## Estado con datos

La lista es el contenido principal. Por defecto ordena por título, con favoritos solo si están realmente en uso. Cada fila muestra máximo tres piezas: título, usuario y origen. Grupo se comunica en detalle o como etiqueta discreta cuando filtra el contexto.

El detalle aparece en panel adyacente cuando hay anchura suficiente y como navegación push en popup o iPhone. No se usan mosaicos de tarjetas.

## Estado bloqueado

Oculta por completo credenciales, búsquedas recientes y previews. Muestra:

- `Space está bloqueado`;
- método disponible y acción `Desbloquear Space`;
- acceso secundario a recovery cuando corresponde;
- motivo específico si hubo timeout, reinicio o revocación.

No se usa un gran candado decorativo. En iOS, la vista queda protegida en el app switcher.

## Cargando y sincronizando

- Primera carga sin cache: estructura mínima y `Cargando tu vault` anunciado una vez.
- Sync en background: indicador textual discreto junto al contexto relevante.
- Cambios pendientes: `Guardado en este dispositivo. Sync pendiente`.
- Error recuperable: conserva contenido y añade `No se pudo sincronizar` con `Volver a intentar sync`.
- Offline: `Sin conexión. Puedes seguir usando los datos de este dispositivo`.

El indicador nunca gira indefinidamente sin texto o timeout.

## Error, conflicto y dato corrupto

- Error de campo vive junto al campo.
- Error de acción vive junto a la acción y conserva los datos introducidos.
- Error global solo cuando la superficie no puede funcionar.
- Conflicto no usa “error” genérico. Etiqueta `Necesita revisión` y conduce al flujo de comparación.
- Un dato corrupto no se descarta. Se aísla, se identifica sin exponer contenido y ofrece diagnóstico seguro o restauración.

## Feedback de copiar y mostrar

- Copiar: cambia temporalmente a `Contraseña copiada`, anuncia por live region polite y vuelve a su etiqueta. No incluye el secreto.
- Mostrar: exige reautenticación según TTL y riesgo. El control cambia entre `Mostrar contraseña` y `Ocultar contraseña`.
- Al perder foco, cambiar de app, bloquear o cumplir timeout, el valor vuelve a enmascararse.
- Un countdown visible se usa solo si ayuda a anticipar el ocultamiento, sin actualización accesible cada segundo.

## Matriz de componentes

Todo control interactivo debe especificar y probar:

| Estado | Evidencia mínima |
| --- | --- |
| Default | etiqueta, rol y valor comprensibles |
| Hover | cambio perceptible, sin depender de movimiento |
| Focus | anillo de 2 px con separación de 2 px y contraste 3:1 |
| Active | respuesta inmediata sin desplazar layout |
| Selected | `aria-selected`, `aria-current` o equivalente nativo cuando aplique |
| Disabled | motivo disponible cerca; preferir no ocultar capacidades relevantes |
| Loading | etiqueta estable, progreso anunciado y doble envío bloqueado |
| Error | mensaje específico asociado y recuperación posible |
| Success | confirmación breve, accesible y sin secreto |

## Movimiento

- Hover y focus: 100 a 150 ms.
- Apertura, cierre y navegación: 160 a 220 ms.
- Inserción, eliminación y reorder: hasta 240 ms si ayuda a conservar posición espacial.
- Curva ease-out quart o equivalente del sistema.
- No hay secuencias de entrada de página, rebote, parallax, blur decorativo ni animación continua.
- Con reduced motion, navegación y cambios de estado son instantáneos o crossfade breve de hasta 100 ms. Ninguna información depende de movimiento.

