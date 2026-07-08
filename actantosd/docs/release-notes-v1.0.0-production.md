# v1.0.0-production Release Notes

## Highlights

- frozen `/v1` API contract for runtime, operator, and MCP gateway integrations
- verified upgrade path from `v0.7.0-pilot-beta` to `v1.0.0-production`
- production release checklist, artifact manifest, and release packaging workflow
- expanded policy template pack to five starter templates
- stable MCP gateway client guidance for production operators

## Upgrade notes

- run `npm run db:migrate` before starting the upgraded service
- the demo tenant policy bundle is backfilled from the old placeholder policy text to the checked-in Cedar source
- `db:seed-demo` remains optional and is only for local demo fixtures

## Verification baseline

- `typecheck`
- `test`
- `build`
- `policy:regression`
- `smoke:fresh-install`

## Known limits

- publishing the GitHub release itself remains an external operator action
- production go/no-go still depends on real pilot evidence outside the local repository
