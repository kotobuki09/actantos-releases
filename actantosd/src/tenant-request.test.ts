import assert from "node:assert/strict"
import test from "node:test"

import {
  resolveRequestTenantId,
  TenantMismatchError,
  TenantRequiredError,
  tenantScopedSurfaces,
} from "./tenant-request.ts"

test("resolveRequestTenantId prefers explicit tenant and never defaults to t_demo", () => {
  assert.equal(
    resolveRequestTenantId({ explicitTenantId: "t_alpha", principalTenantId: "t_alpha" }),
    "t_alpha",
  )
  assert.equal(
    resolveRequestTenantId({ principalTenantId: "t_from_principal" }),
    "t_from_principal",
  )
  assert.throws(
    () => resolveRequestTenantId({}),
    (error: unknown) => error instanceof TenantRequiredError,
  )
  assert.throws(
    () => resolveRequestTenantId({ explicitTenantId: "t_alpha", principalTenantId: "t_beta" }),
    (error: unknown) => error instanceof TenantMismatchError,
  )
})

test("tenant surface inventory covers control-plane families without demo fallbacks", () => {
  assert.ok(tenantScopedSurfaces.length >= 12)
  const ids = tenantScopedSurfaces.map((surface) => surface.id)
  for (const required of ["sessions", "decisions", "budgets", "kill_switches", "policy_bundles", "evidence_export"]) {
    assert.ok(ids.includes(required as (typeof ids)[number]), `missing surface ${required}`)
  }
  for (const surface of tenantScopedSurfaces) {
    assert.match(surface.path, /^\//u)
    assert.ok(surface.methods.length > 0)
  }
})
