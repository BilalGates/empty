# Accesibilidad

## Objetivo

Space apunta a WCAG 2.2 AA en superficies web y extensión, y a los patrones de accesibilidad nativos de iOS. Para texto principal se busca contraste 7:1 cuando no comprometa estados semánticos.

## Teclado y foco

- Toda función está disponible sin puntero.
- Orden de tabulación coincide con el orden visual y no entra en contenido inerte.
- Al abrir un diálogo, el foco entra, queda contenido y vuelve al disparador al cerrar.
- En listas, se elige un patrón coherente: tab por acción o navegación compuesta con flechas. No se mezclan sin instrucción.
- Shortcuts nunca sustituyen controles visibles y evitan conflictos con navegador, lector de pantalla o sistema.
- El foco no se pierde tras guardar, eliminar, filtrar o actualizar la lista.

## Lectores de pantalla

- Cada pantalla tiene título y regiones semánticas.
- Filas de credencial anuncian título, usuario y origen, nunca password.
- Iconos de acción tienen nombre y estado. Decorativos se ocultan del árbol.
- Mensajes de copia, guardado y error usan live regions con prioridad proporcionada.
- El estado de sync no se anuncia en cada cambio menor. Solo fallo, recuperación o finalización relevante.
- Password enmascarada no expone longitud real si eso aumenta riesgo.

## Zoom, tamaño y reflow

- Web funciona al 200% sin pérdida y, donde WCAG lo exija, a 400% con reflow hasta 320 CSS px.
- No hay scroll bidimensional para formularios o contenido textual.
- iOS usa Dynamic Type y layouts que crecen verticalmente. Las acciones críticas nunca se truncan.
- Objetivos: mínimo 24 por 24 CSS px según WCAG, objetivo de producto 40 por 40 px; iOS 44 por 44 pt.
- El contenido respeta safe areas, teclado en pantalla y orientación soportada.

## Contraste y percepción

- Texto normal 4.5:1; grande 3:1; foco y límites necesarios 3:1 contra adyacentes.
- Placeholder cumple contraste y no sustituye etiqueta.
- Error, warning, success, selección y conflicto combinan color con texto, icono o forma.
- Se prueban forced colors en Windows, Increase Contrast y Differentiate Without Color en iOS.
- Los logos de sitios no son el único medio para identificar una credencial.

## Movimiento y tiempo

- `prefers-reduced-motion` y Reduce Motion de iOS eliminan desplazamientos y reorders animados.
- Los timeouts de bloqueo son configurables dentro de límites seguros y avisan antes de cerrar una tarea no sensible cuando sea posible.
- Copia al portapapeles y revelado tienen duración comprensible; el usuario puede ocultar manualmente antes.
- No hay contenido con flashes ni animación automática decorativa.

## Lenguaje y cognición

- Frases cortas, verbos concretos y una decisión por diálogo.
- Riesgo y consecuencia preceden a la acción irreversible.
- Cuenta, vault, dispositivo y recovery mantienen el mismo nombre en todas las superficies.
- Errores responden qué ocurrió, qué se conserva y qué puede hacer la persona.
- Recuperación no usa dobles negaciones ni eufemismos sobre pérdida de datos.

## Privacidad accesible

La accesibilidad no debe filtrar secretos:

- nombres accesibles no incluyen password, TOTP, recovery key ni notas;
- announcements confirman la acción, no el valor;
- la semántica de campos secretos se verifica con VoiceOver, NVDA y accesibilidad de Chrome;
- automatización y snapshots de tests sustituyen secretos por fixtures;
- copiar o mostrar nunca coloca el valor en tooltip, atributo title, aria-label o DOM fuera del contexto mínimo.

## Gate verificable

Antes de cada release:

1. axe u otra comprobación automática sin violaciones Critical o Serious justificables.
2. Recorrido manual completo con teclado en Chrome.
3. Recorrido con NVDA o equivalente y VoiceOver en iPhone real o entorno válido.
4. Prueba a 200% y 400% web, Dynamic Type máximo relevante y pseudolocalización.
5. Prueba de reduced motion, forced colors y contraste aumentado.
6. Registro de defectos por flujo, no solo por componente.

