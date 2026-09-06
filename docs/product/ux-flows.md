# Flujos UX

## Onboarding y primer secreto

1. **Bienvenida:** explica en dos frases que Space guarda un vault cifrado y que el servidor no puede recuperarlo por sí solo. Acción: `Crear mi vault`.
2. **Cuenta:** passkey cuando esté disponible o método soportado. No se pide todavía la contraseña maestra.
3. **Vault:** crear contraseña maestra, confirmar y comprobar requisitos mientras se escribe. Nunca se usa una “puntuación” teatral.
4. **Recovery:** generar recovery key, guardarla y verificar una parte. Explicar con lenguaje literal qué ocurre si se pierden todos los métodos.
5. **Vault vacío:** superficie casi vacía, texto breve y acción `Crear credencial`. Acción secundaria discreta: `Importar credenciales` cuando M5 esté disponible.
6. **Primera creación:** título, origen, usuario, contraseña y grupo opcional. El generador está junto al campo contraseña.
7. **Éxito:** mostrar la credencial en su lugar natural y ofrecer `Usar en Chrome` o instrucciones de AutoFill iOS según plataforma, no un modal celebratorio.

## Encontrar y usar una credencial

1. Abrir Space sitúa el foco en búsqueda si hay teclado físico, salvo que la apertura provenga de un campo detectable.
2. La lista muestra título, usuario y origen. Contraseña, notas y timestamps no aparecen en la lista.
3. Seleccionar abre el detalle sin perder la posición de búsqueda.
4. `Copiar usuario`, `Copiar contraseña`, `Mostrar contraseña` y `Editar credencial` son acciones inequívocas.
5. Copiar confirma mediante texto accesible y visual durante un intervalo breve. No reproduce el secreto en el mensaje.
6. Al volver, búsqueda, scroll y selección se conservan durante la sesión desbloqueada.

## Chrome: rellenar en una página

1. El popup identifica el origen actual en la cabecera de contenido, sin URL completa ruidosa.
2. Si está bloqueado, la acción primaria es `Desbloquear Space`.
3. Con una coincidencia segura, la credencial ocupa el primer plano y la acción es `Rellenar credencial`.
4. Con varias coincidencias, se listan por título y usuario. La más reciente no se preselecciona de forma destructiva.
5. Sin coincidencias, se ofrece `Buscar en Space`; `Crear para este sitio` aparece solo si se detecta un formulario compatible.
6. Una coincidencia aproximada nunca se rellena como exacta. Se explica la diferencia y la acción requiere elección explícita.
7. Tras rellenar, el popup puede cerrarse. El anuncio accesible ocurre antes del cierre cuando sea necesario.

## Guardar login nuevo o actualizar password

1. Tras envío exitoso detectado, aparece una invitación no modal en contexto confiable de la extensión.
2. Para login nuevo: mostrar origen, usuario y contraseña enmascarada; acciones `Guardar credencial` y `Ahora no`.
3. Para una credencial existente: comparar localmente y ofrecer `Actualizar contraseña`.
4. Si hay ambigüedad, pedir seleccionar la credencial. Nunca sobrescribir por similitud de usuario.
5. La cancelación no vuelve a preguntar repetidamente durante la misma visita.

## Crear o editar

- Validación en línea después de interacción o submit, no al enfocar por primera vez.
- Guardar mantiene al usuario en el detalle y anuncia `Credencial guardada`.
- Salir con cambios pregunta `Descartar cambios` o `Seguir editando`.
- Eliminar vive al final de edición. Requiere confirmación con título visible y acción `Eliminar credencial`.
- Si la credencial cambió en otro dispositivo, no se permite guardar encima sin resolver.

## Conflicto de sync

1. La credencial permanece disponible en modo seguro y se marca `Necesita revisión`.
2. La comparación muestra valores locales y remotos para título, usuario, orígenes, grupo y notas. Password permanece enmascarada.
3. Acciones: `Conservar esta versión`, `Usar la otra versión` o `Combinar campos` cuando sea seguro.
4. Elegir una versión requiere reautenticación si reemplaza password o material sensible.
5. La resolución crea una revisión nueva. No borra silenciosamente ninguna revisión antes de que la operación quede persistida.

## Recovery y pérdida

1. Elegir método disponible: recovery key, segundo dispositivo aprobado o segundo factor configurado.
2. Mostrar qué recupera el método y qué no.
3. Verificar el método antes de alterar envelopes o revocar dispositivos.
4. Recuperar, sincronizar y validar una muestra localmente.
5. Invitar a rotar credenciales comprometidas y crear una recovery key nueva cuando proceda.

El estado sin ningún método válido es terminal: Space explica que el vault no puede descifrarse. No ofrece soporte como vía ficticia de recuperación.

## Importación

1. Seleccionar formato y archivo local.
2. Mostrar advertencia de texto plano antes de abrir el selector cuando corresponda.
3. Analizar localmente, sin upload.
4. Presentar resumen: válidas, posibles duplicados, inválidas y omitidas.
5. Permitir revisar duplicados sin mostrar todas las contraseñas.
6. Cifrar y guardar solo tras confirmación.
7. Recomendar borrar el original y enlazar instrucciones específicas del sistema.

## Exportación

- Opción recomendada: `Crear backup cifrado`.
- CSV está bajo `Exportar sin cifrado`, nunca al mismo nivel visual.
- Ambos requieren reautenticación.
- Antes de CSV, mostrar destino, riesgo, contenido incluido y acción literal `Exportar CSV sin cifrar`.

