# Revisión crítica de la propuesta

## Hallazgos

### High: la promesa de minimalismo puede ocultar estado de seguridad

Una interfaz demasiado vacía podría esconder origen, bloqueo, sync o conflicto. La solución no es añadir un dashboard: cada estado aparece junto a la acción afectada y el origen precede a cualquier relleno. Criterio de rechazo: un participante rellena sin poder decir en qué dominio lo hará.

### High: un popup ambicioso sería frágil e inaccesible

Editar notas, recovery, dispositivos e importación dentro del popup elevaría densidad, recortes y pérdida de estado al cerrarse. El popup queda limitado a desbloquear, buscar, rellenar, copiar, mostrar, generar y proponer guardado. La gestión completa abre Space.

### High: “misma experiencia” entre Chrome e iOS puede producir UI no nativa

La paridad se limita a reglas, vocabulario y seguridad. iOS conserva NavigationStack, sheets, Face ID y AutoFill del sistema. Chrome conserva popup y contexto de extensión. Criterio de rechazo: una captura de iOS parece una web embebida o el popup parece una app móvil encogida.

### Medium: el violeta puede leerse como estética SaaS genérica

El seed propuesto cae cerca de una convención popular. Se mitiga reduciendo su presencia a foco y acción, sin gradientes, resplandores ni fondos tintados extensos. Antes de congelar marca, probar una variante monocroma y otra con el mismo hue a menor croma. Elegir por reconocimiento y confianza, no por preferencia interna.

### Medium: la lista mínima puede quedarse corta con vaults grandes

Título, usuario y origen funcionan hasta que hay cientos de credenciales similares. M1 debe medir búsqueda y duplicados. M2 puede añadir recencia o favoritos solo con evidencia. No introducir metadatos permanentes en cada fila por anticipación.

### Medium: copy de zero-knowledge puede crear falsa seguridad

“El servidor no puede leer tu vault” no cubre malware local, content script comprometido o secretos mostrados. Onboarding y ayuda deben diferenciar protección del servidor y límites del dispositivo, sin volcar el threat model en cada pantalla.

### Medium: recovery key verificada puede aumentar abandono

Omitirla crea daño mayor. Se mantiene obligatoria antes de depender del vault, pero se probarán momento, explicación y métodos de guardado. No se reduce a una checkbox de aceptación.

### Low: ausencia total de ilustración puede sentirse clínica

No es un problema funcional. La personalidad puede venir de ritmo, lenguaje, iconografía precisa y transiciones de estado. Una ilustración solo se añade si enseña un concepto y tiene alternativa accesible; nunca para rellenar vacío.

## Hipótesis que requieren validación

- que crear cuenta antes que master password produce mejor comprensión que el orden inverso;
- que 340 a 400 px permite un popup cómodo en los entornos objetivo;
- que revelar password debe exigir reautenticación con el mismo TTL que exportar;
- que favoritos justifican presencia en V1;
- que el grupo debe aparecer en cada fila al filtrar;
- que la recuperación obligatoria no bloquea desproporcionadamente la activación.

## Checklist de rechazo visual

La propuesta falla la revisión si ocurre cualquiera:

- la primera pantalla con datos contiene más superficie de navegación o chrome que de credenciales;
- se repiten tres o más tarjetas equivalentes para acciones primarias;
- aparece una métrica sin decisión directa asociada;
- el color se usa para ornamentar más de una décima parte de la superficie habitual;
- un secreto aparece en lista sin acción deliberada;
- foco, error o selección dependen solo de un cambio de violeta;
- la UI necesita una leyenda para explicar iconos de acciones comunes;
- el popup requiere más de un nivel de navegación para rellenar una coincidencia exacta;
- la versión iOS ignora Dynamic Type o patrones nativos para conservar similitud visual.

## Evidencia necesaria antes de congelar el sistema

1. Prototipos a escala real de popup en los diez estados definidos.
2. Pantallas iOS en tamaño pequeño y con Dynamic Type accesible.
3. Medición automatizada y manual de contraste de tokens y estados.
4. Recorrido teclado, NVDA y VoiceOver de los flujos críticos.
5. Prueba con vault vacío, 20, 500 y 5.000 credenciales.
6. Test de dominios exactos, subdominios, IDN, homógrafos y puertos.
7. Prueba de comprensión de recovery, conflicto y exportación sin cifrar.

