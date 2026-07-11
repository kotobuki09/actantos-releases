# T3 verification
- Commit: ce6b83a feat(tenancy): enforce tenant schema and rls
- Integration merge: 176f647
- Unit tests: 176 pass (pg-mem path skips 008_tenant_rls.sql)
- Migrations: 007_tenant_identity.sql, 008_tenant_rls.sql
- Helper: withTenantTransaction / tenantContextSql
