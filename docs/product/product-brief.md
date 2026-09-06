# Space: definición de producto

## Propósito

Space es un gestor de credenciales personal y zero-knowledge para Chrome y iPhone. Permite guardar, encontrar, rellenar, actualizar y recuperar credenciales sin que el servicio pueda leer el vault.

El producto separa dos conceptos que la interfaz debe explicar con precisión:

- **Acceder a Space** autentica la cuenta y el dispositivo frente al servicio.
- **Desbloquear el vault** obtiene localmente la clave necesaria para descifrar los datos.

La experiencia no promete eliminar decisiones de seguridad. Las reduce, las ordena y explica sus consecuencias en el momento adecuado.

## Personas y contexto

### Persona principal

Una persona que ya guarda contraseñas en el navegador o el teléfono y quiere una fuente de verdad propia, sincronizada y comprensible. Alterna entre Chrome y iPhone, espera que AutoFill funcione y no quiere administrar infraestructura ni comprender criptografía.

### Persona avanzada

Una persona que usa passkeys, TOTP o YubiKey, exige exportación, recuperación verificable, control de dispositivos y señales claras antes de una acción sensible.

### Trabajos principales

1. Entrar en un servicio con la credencial correcta y en el origen correcto.
2. Crear o guardar una credencial sin interrumpir la tarea actual.
3. Encontrar, copiar, mostrar o editar un secreto con el mínimo de exposición.
4. Recuperar el vault o revocar un dispositivo con consecuencias explícitas.
5. Importar credenciales localmente y entender qué se creó, omitió o dejó pendiente.

## Promesa de experiencia

Space se siente tranquilo, directo y privado. La interfaz desaparece detrás de las credenciales. No parece un panel de administración, una terminal ni un producto SaaS de analítica.

## Principios

1. **La credencial es la interfaz.** Cuando hay datos, la lista y el detalle dominan. Navegación, métricas y configuración no compiten con ellos.
2. **Una acción principal por contexto.** Crear en un vault vacío, rellenar en una página, guardar tras un alta, resolver en un conflicto.
3. **Seguridad visible cuando decide algo.** El origen, el estado de bloqueo, la reautenticación y las consecuencias irreversibles son explícitos. El cifrado no se usa como decoración.
4. **Explicación progresiva.** El camino habitual es breve. Recovery, conflicto y exportación muestran detalle suficiente antes de confirmar.
5. **Misma lógica, patrón nativo.** Chrome e iOS comparten vocabulario y reglas, pero respetan sus convenciones de interacción.

## Alcance de datos

El modelo admite desde el inicio Password, Passkey, TOTP y RecoveryCode o elemento seguro. En los primeros hitos, Password es la única modalidad obligada a completar de extremo a extremo. La interfaz no muestra tipos aún inoperantes como si estuvieran disponibles.

Una credencial Password incluye: título, uno o más orígenes o URL, usuario, contraseña, grupo opcional, notas opcionales, favoritos cuando aporten acceso rápido, timestamps y metadata de versión. Los campos personalizados quedan fuera de V1 salvo evidencia de uso.

Los grupos son planos. Una credencial puede no pertenecer a ninguno. Buscar siempre cruza todos los grupos.

## Límites explícitos

- No hay estadísticas de uso, puntuaciones agregadas ni widgets en la pantalla principal.
- No hay jerarquías de carpetas anidadas en V1.
- No hay feed de actividad en la navegación primaria.
- No se presenta la integración con Apple Passwords como sincronización bidireccional privada.
- No se promete recuperar el vault si se pierden todos los métodos de desbloqueo y la recovery key.
- No se rellena una credencial en un origen parecido. La coincidencia debe ser exacta o requerir elección informada.

## Métricas de producto, fuera de la interfaz principal

Las métricas sirven al equipo, no como decoración para el usuario:

- tasa de finalización de creación y primer relleno;
- tiempo mediano desde abrir el popup hasta rellenar;
- porcentaje de usuarios que verifican recovery;
- tasa de fallos de AutoFill por clase de formulario;
- conflictos de sync detectados y resueltos sin pérdida;
- abandonos en importación, exportación y recuperación.

No deben incluir secretos, nombres de credenciales, URLs completas, notas ni identificadores correlacionables innecesarios.

