# Criterios de aceptación de producto

## Matriz común por flujo

Cada flujo crítico se prueba en estos estados cuando apliquen:

| Dimensión | Casos mínimos |
| --- | --- |
| Vault | bloqueado, desbloqueado, sesión expirada |
| Datos | vacío, uno, muchos, dato largo, dato incompleto, dato corrupto |
| Red | online, offline, lenta, timeout, reintento, sesión revocada |
| Sync | al día, pendiente, conflicto, rollback detectado |
| Entrada | puntero, solo teclado, lector de pantalla, dictado cuando aplique |
| Visual | 200% zoom web, Dynamic Type accesible, contraste aumentado, modo claro y oscuro si se soporta |
| Movimiento | normal y reduced motion |
| Localización | español, inglés y pseudolocalización con expansión del 40% |

## Criterios globales verificables

- En la pantalla principal no existen métricas, gráficas, widgets, actividad reciente ni paneles secundarios sin relación con encontrar o crear una credencial.
- En estado vacío hay como máximo una acción primaria y dos secundarias visibles.
- En estado con datos, al menos el 60% del área útil inicial se dedica a credenciales, búsqueda o detalle.
- Ningún secreto se muestra por defecto en listas, resultados, notificaciones, mensajes de error, logs o selector de aplicaciones.
- Toda acción sensible nombra objeto y consecuencia. No se usan `OK`, `Sí` o `Continuar` cuando exista una etiqueta más precisa.
- Toda afirmación de guardado o sync refleja un estado confirmado, no optimista, salvo que se etiquete como pendiente.
- Volver desde detalle conserva consulta, scroll y selección.
- Un usuario puede crear, buscar, copiar, editar y bloquear usando solo teclado.
- Los avisos de origen muestran dominio efectivo legible y permiten inspeccionar la URL completa sin truncamiento ambiguo.

## Pruebas de comprensión

Antes de release candidate, pruebas moderadas con al menos cinco participantes deben demostrar:

- 5 de 5 entienden que soporte no puede recuperar el vault sin un método válido;
- 4 de 5 distinguen cuenta y vault sin recurrir a terminología criptográfica;
- 4 de 5 detectan correctamente una advertencia por dominio parecido;
- 4 de 5 completan importación y pueden explicar qué archivos siguen en texto plano;
- 4 de 5 resuelven un conflicto sin creer que Space combinó passwords automáticamente.

Un fallo no se corrige añadiendo más texto por defecto. Primero se revisan orden, etiqueta, agrupación y momento de la información.

