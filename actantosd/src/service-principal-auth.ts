import { createHash, timingSafeEqual } from "node:crypto"
import type { AuthenticatedPrincipal, TenantRole } from "./oidc-auth.ts"

export type ServicePrincipal = {
  readonly id: string
  readonly secretHash: string
  readonly tenantId: string
  readonly role: TenantRole
  readonly scopes: readonly string[]
}

export interface ServicePrincipalResolver {
  resolve(id: string): Promise<ServicePrincipal | undefined>
}

export const verifyServicePrincipal = async (
  authorization: string | undefined, resolver: ServicePrincipalResolver,
): Promise<AuthenticatedPrincipal | null> => {
  if (authorization === undefined || !authorization.startsWith("Service ")) return null
  const [id, secret] = authorization.slice(8).split(":", 2)
  if (id === undefined || secret === undefined || id.length === 0 || secret.length === 0) return null
  const service = await resolver.resolve(id)
  if (service === undefined) return null
  const actual = createHash("sha256").update(secret).digest()
  const expected = Buffer.from(service.secretHash, "hex")
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null
  return { kind: "service", subject: service.id, issuer: "actantos:service", audience: "actantos-runtime",
    tenantId: service.tenantId, memberships: [{ tenantId: service.tenantId, role: service.role, scopes: service.scopes }],
    role: service.role, scopes: service.scopes }
}
