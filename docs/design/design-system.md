# Sistema de diseño Space

## Dirección

**Escena:** un instrumento personal silencioso, abierto sobre una mesa clara durante una tarea cotidiana. Debe transmitir control y calma sin parecer un panel corporativo.

**Estrategia de color:** restringida. Blanco o negro neutro sostiene el contenido; violeta y estados semánticos ocupan menos del 10% de la superficie.

Anti-referencias:

- dashboard con rail lateral, KPIs, gráficas y widgets;
- terminal oscura con tipografía monoespaciada como identidad;
- SaaS con cabeceras degradadas, tarjetas flotantes y navegación sobredimensionada;
- cajas para cada bloque, glassmorphism, sombras difusas y radios exagerados;
- iconos de candados, escudos o “cifrado militar” usados como decoración.

## Color

Tokens base en OKLCH:

```css
:root {
  --space-bg: oklch(1 0 0);
  --space-surface-subtle: oklch(0.965 0.004 270);
  --space-surface-raised: oklch(0.985 0.002 270);
  --space-ink: oklch(0.19 0.012 270);
  --space-ink-muted: oklch(0.43 0.015 270);
  --space-line: oklch(0.88 0.007 270);
  --space-primary: oklch(0.56 0.12 270);
  --space-primary-hover: oklch(0.50 0.13 270);
  --space-primary-soft: oklch(0.94 0.025 270);
  --space-on-primary: oklch(1 0 0);
  --space-accent: oklch(0.46 0.11 210);
  --space-danger: oklch(0.52 0.17 28);
  --space-warning: oklch(0.57 0.12 75);
  --space-success: oklch(0.47 0.11 152);
  --space-focus: oklch(0.62 0.17 270);
}
```

Estos valores son tokens de intención, no garantía de contraste. La implementación debe medir cada pareja renderizada. Texto normal exige 4.5:1 como mínimo, texto grande 3:1 y componentes o foco 3:1 contra colores adyacentes. El objetivo para `ink` sobre `bg` es 7:1.

Modo oscuro, si se incluye en el milestone:

```css
[data-theme="dark"] {
  --space-bg: oklch(0.10 0 0);
  --space-surface-subtle: oklch(0.15 0.006 270);
  --space-surface-raised: oklch(0.18 0.007 270);
  --space-ink: oklch(0.94 0.006 270);
  --space-ink-muted: oklch(0.72 0.012 270);
  --space-line: oklch(0.30 0.009 270);
  --space-primary: oklch(0.70 0.12 270);
  --space-primary-hover: oklch(0.76 0.11 270);
  --space-primary-soft: oklch(0.24 0.04 270);
  --space-on-primary: oklch(0.10 0 0);
  --space-focus: oklch(0.76 0.14 270);
}
```

El color nunca es el único indicador de error, selección, sync o conflicto.

## Tipografía

- Chrome/web: `Inter`, seguida de `system-ui`, sin cargar más familias por defecto.
- iOS: San Francisco mediante estilos semánticos de SwiftUI.
- Mono se reserva a recovery keys, códigos y fragmentos técnicos que requieren diferenciación de caracteres. Nunca se usa como voz global.
- Base web: 16 px. Escala: 12, 14, 16, 18, 22, 28 y 36 px.
- Peso normal 400 o 450; etiquetas y acciones 550 o 600; títulos hasta 650.
- Texto de lectura limitado a 70 caracteres. Los valores pueden romper línea; nunca se recortan de forma irreversible.
- Sentence case para todos los controles. No hay eyebrows en mayúsculas.

## Espacio y composición

- Unidad base: 4 px. Escala: 4, 8, 12, 16, 24, 32, 48 y 64.
- Densidad por defecto cómoda. Popup ligeramente compacto, sin bajar objetivos interactivos.
- Radio: 6 px para inputs, 8 px para botones y 12 px máximo para superficies agrupadas. Pills solo para etiquetas que semánticamente lo requieran.
- Bordes de 1 px separan campos o regiones solo cuando el espacio no basta. No se combinan con sombras decorativas.
- Sombra máxima: elevación funcional breve, sin borde simultáneo. Menús, popovers y confirmaciones pueden usarla.
- La jerarquía se construye con posición, espacio y tipo. Una card no es el contenedor por defecto.

## Iconografía

- Un único set outline, trazo coherente, 16, 20 y 24 px.
- Todo icono sin texto tiene nombre accesible y tooltip cuando la acción no sea universal.
- Copiar, mostrar y editar pueden usar icono más etiqueta en superficies amplias. En popup compacto, el icono solo es válido si el nombre accesible y el patrón son inequívocos.
- No usar escudos, candados, estrellas o destellos como decoración.

## Componentes esenciales

### Botón

Variantes: primary, secondary y quiet; danger solo para acción destructiva confirmada. Altura mínima web 40 px y objetivo táctil iOS 44 por 44 pt. Un grupo no muestra más de una acción primary.

### Campo

Etiqueta persistente arriba. Placeholder es ejemplo, no sustituto. Error bajo el campo y asociado programáticamente. Password incluye mostrar/ocultar como control separado y anuncia el estado, no el valor.

### Fila de credencial

No es una card. Es una fila dentro de una lista continua con título, usuario y origen. Selección mediante fondo sutil, peso y marcador accesible. Acciones rápidas aparecen en hover y foco, pero siguen disponibles con teclado y touch.

### Detalle de credencial

Orden: identidad, origen, usuario, password, notas, grupo y acciones de mantenimiento. Cada valor tiene etiqueta visible. Copiar confirma sin revelar el contenido.

### Aviso

Texto específico, icono semántico y acciones claras. Un aviso de phishing u origen diferente no puede descartarse por accidente con la misma jerarquía que `Rellenar`.

### Diálogo

Último recurso para decisiones bloqueantes, destructivas o de reautenticación. Título describe la decisión. El foco inicial va a la opción segura, no a la destructiva.

## Voz

Breve, literal y humana. “Space está bloqueado” es preferible a “Sesión no disponible”. “No se pudo sincronizar. Tus cambios siguen guardados en este dispositivo” explica estado y consecuencia.

Etiquetas:

- `Crear credencial`, no `Nueva`;
- `Copiar contraseña`, no `Copiar`;
- `Exportar CSV sin cifrar`, no `Continuar`;
- `Bloquear Space`, no `Cerrar`;
- `Volver a intentar sync`, no `Reintentar operación`.

