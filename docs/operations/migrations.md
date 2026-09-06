# Database migration operations

Migrations are immutable after any shared environment applies them. Use ordered, transactional SQL and an expand/contract sequence for changes that cannot be deployed atomically with both old and new application versions.

Before deployment, test from an empty database and from a sanitized schema/data fixture matching the previous production release. Record duration, locks taken, disk growth and the forward-fix procedure. Never use a destructive migration (`DROP`, `TRUNCATE`, narrowing conversion) without a reviewed backup, compatibility window and recovery rehearsal.

The API startup advisory lock prevents two replicas from applying migrations simultaneously. For long-running production migrations, run the migration as a separate controlled job before scaling the new API. A failed migration blocks readiness; do not bypass or manually mark it applied.

Rollback normally means rolling the application back while leaving compatible expanded schema in place. Once a contract migration has removed old data or structure, restore or forward-fix according to the rehearsed plan rather than editing migration history.
