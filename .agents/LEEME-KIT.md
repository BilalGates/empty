# Kit de agentes

Un equipo de 8 agentes, la skill central `filigrana` (criterio de código, diseño, auditoría y delegación entre motores) y un juego de skills que funcionan igual en **Claude Code, Codex, OpenCode y Antigravity**, y que se adaptan a cada proyecto mediante una inducción.

## El equipo

| Nombre | id | Rol |
|---|---|---|
| Pep Guardiola | `pep` | Project manager: entra en cada sesión, reparte y cierra con Larry |
| Luisito Comunica | `luisito` | Explorador de solo lectura |
| Steve Smith | `steve` | Arquitecto |
| Rahul Singh | `rahul` | Constructor todoterreno |
| Aniol Catalán | `aniol` | Revisor adversarial |
| Dani Holanda | `dani` | Verificador (tests, CI, aceptación) |
| Larry | `larry` | Git y GitHub: commits rápidos y consultas del repo (nunca push ni merge) |
| Jose Plasencia | `jose` | Operador de infraestructura |

## Instalar en un proyecto

Requisitos: Node 18+ y git.

1. Desde cualquier carpeta del proyecto ejecuta:
   ```bash
   filigranas   # alias de: node ~/repositorios/filigranas/kit-agentes/scripts/agentes/instalar.mjs
   ```
   Copia el kit a la raíz (un `AGENTS.md` propio pasa a `.agents/proyecto.md`; un `.githooks` propio no se toca), activa los git hooks salvo que ya haya otro gestor (husky), crea `CLAUDE.md` apuntando a `AGENTS.md` y genera los agentes para cada herramienta. Volver a ejecutarlo **actualiza** el kit.
2. Abre el proyecto con tu herramienta y pide: **"Pep, haz la inducción del proyecto"**. Pep analiza el repositorio y escribe `.agents/proyecto.md` (stack, comandos, ramas, reglas), y te propone las skills propias del proyecto.
3. Commitea el resultado (o pídeselo a Larry).

Opcional, en `package.json`:

```json
"agentes:sync": "node scripts/agentes/sincronizar.mjs",
"agentes:check": "node scripts/agentes/sincronizar.mjs --check",
"agentes:commits": "node scripts/agentes/agrupar-commits.mjs"
```

y en CI un paso con `node scripts/agentes/sincronizar.mjs --check`.

## Cómo está organizado

```
AGENTS.md                      fichero principal (todas las herramientas lo leen)
.agents/proyecto.md            perfil del proyecto (lo crea la inducción) — manda sobre lo genérico
.agents/agents/<id>/agent.md   fichas de los agentes — FUENTE ÚNICA (Antigravity la lee tal cual)
.agents/skills/<skill>/        skills — fuente única (Codex, OpenCode y Antigravity las leen aquí)
.agents/reglas.mjs             opcional: reglas comprobables por commit
scripts/agentes/               sincronizar, agrupar commits, instalar, hooks
.githooks/                     pre-commit y commit-msg (avisan, nunca bloquean)

GENERADO (no editar a mano; `node scripts/agentes/sincronizar.mjs`):
.claude/agents/*.md   .claude/skills/   .codex/agents/*.toml   .opencode/agents/*.md
```

## Cambiar algo

- Un agente: edita `.agents/agents/<id>/agent.md` y sincroniza.
- Modelo por nivel (`barato`/`medio`/`fuerte`/`maximo`) y por motor: `.agents/skills/filigrana/scripts/niveles.json` (lo usan `sincronizar.mjs` y `delegar.mjs`).
- Tu gusto de diseño: `.agents/skills/filigrana/reference/gusto.md`.
- Una skill nueva: `.agents/skills/<nombre>/SKILL.md` con cabecera `name` y `description` (entre comillas si lleva `: `), añádela al índice de `AGENTS.md` y sincroniza.

## Límites conocidos

- **Codex** no lanza subagentes por nombre: al delegar se le indica "Actúa según `.agents/agents/<id>/agent.md`" (ya lo dice `AGENTS.md`).
- **OpenCode 2.0.12** ignora los permisos con la sintaxis nueva; el generador usa la antigua.
- Los git hooks se activan por clon (`instalar.mjs` o `git config core.hooksPath .githooks`).
