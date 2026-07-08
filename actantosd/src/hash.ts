import { createHash, createHmac } from "node:crypto"

export type JsonValue =
  | boolean
  | null
  | number
  | string
  | JsonValue[]
  | { readonly [key: string]: JsonValue }

export const toJsonValue = (value: unknown): JsonValue => {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "number" ||
    typeof value === "string"
  ) {
    return value
  }

  if (Array.isArray(value)) {
    return value.map(toJsonValue)
  }

  if (typeof value === "object") {
    const entries = Object.entries(value).map(([key, nestedValue]) => [
      key,
      toJsonValue(nestedValue),
    ])

    return Object.fromEntries(entries)
  }

  return String(value)
}

const sortJson = (value: JsonValue): JsonValue => {
  if (Array.isArray(value)) {
    return value.map(sortJson)
  }

  if (value !== null && typeof value === "object") {
    const sortedEntries = Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nestedValue]) => [key, sortJson(nestedValue)] as const)

    return Object.fromEntries(sortedEntries)
  }

  return value
}

export const canonicalStringify = (value: JsonValue): string =>
  JSON.stringify(sortJson(value))

export const canonicalHash = (value: unknown): string =>
  sha256(canonicalStringify(toJsonValue(value)))

export const sha256 = (value: string): string =>
  createHash("sha256").update(value).digest("hex")

export const signDecisionToken = (payload: string, secret: string): string =>
  `${Buffer.from(payload, "utf8").toString("base64url")}.${createHmac("sha256", secret).update(payload).digest("base64url")}`

export const verifyDecisionToken = (
  token: string,
  secret: string,
): { readonly valid: true; readonly payload: string } | { readonly valid: false } => {
  const [encodedPayload, signature] = token.split(".")

  if (encodedPayload === undefined || signature === undefined) {
    return { valid: false }
  }

  let payload: string

  try {
    payload = Buffer.from(encodedPayload, "base64url").toString("utf8")
  } catch {
    return { valid: false }
  }

  const expectedSignature = createHmac("sha256", secret)
    .update(payload)
    .digest("base64url")

  if (signature !== expectedSignature) {
    return { valid: false }
  }

  return { valid: true, payload }
}
