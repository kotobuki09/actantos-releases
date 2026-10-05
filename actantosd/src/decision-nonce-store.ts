/**
 * Single-use nonce tracking for decision tokens (invariant S9).
 *
 * ## Two implementations, one contract
 *
 * `InMemoryDecisionNonceStore` is the local half: a `Set` in this process. It is what the unit
 * tests inject and what a single-process deployment can use. It is **not** restart-safe, and the
 * test file asserts that limitation rather than leaving it in prose only.
 *
 * `ReplayStoreDecisionNonceStore` is the durable half, backed by the same `ReplayStore` the
 * effect gateway uses. It is what a deployment that must survive an executor restart uses, and it
 * is what the production caller wires in.
 *
 * ## Why the consume is async
 *
 * An earlier version of this file argued the executor could not use `ReplayStore` because
 * `consume` is async and "an await between 'token is valid' and 'container starts' is a window".
 * That reasoning was wrong, and it is worth correcting rather than deleting, because it is the
 * kind of argument that keeps a real gap open.
 *
 * The guarantee S9 asks for is that a token authorises at most one execution. Awaiting an atomic
 * first-use claim does not weaken that:
 *
 * - Two callers racing the same token are resolved *by the database*, which grants `"consumed"`
 *   to exactly one. The await is where the loser learns it lost.
 * - The spawn happens strictly after the claim resolves to consumed. If the process dies in
 *   between, the token is spent and nothing ran — a wasted authorization, which fails closed.
 *   The unsafe ordering would be spawning first and recording afterwards.
 * - `ReplayStore.consume` returns `unavailable` rather than throwing, so a database outage cannot
 *   be mistaken for a successful claim. This store maps anything that is not `"consumed"` to
 *   false, which fails closed in the one direction that matters.
 */

import type { ReplayStore } from "./v2/replay-store.ts"

/**
 * The identity of one authorization. Mirrors `ReplayEntry` so the durable adapter is a
 * pass-through rather than a translation that could drop a field.
 */
export type DecisionNonceEntry = {
  readonly tenantId: string
  /** The decision id that authorized this execution. */
  readonly permitId: string
  readonly nonce: string
  readonly expiresAt: Date
}

export interface DecisionNonceStore {
  /**
   * Claim first use. Resolves true only for the first caller for a given nonce.
   *
   * Must not resolve true when the underlying store cannot answer.
   */
  consume(entry: DecisionNonceEntry): Promise<boolean>
  /** Read-only. Never used to authorise. */
  isConsumed(entry: DecisionNonceEntry): Promise<boolean>
}

export class InMemoryDecisionNonceStore implements DecisionNonceStore {
  readonly #consumed = new Set<string>()

  async consume(entry: DecisionNonceEntry): Promise<boolean> {
    if (this.#consumed.has(entry.nonce)) {
      return false
    }

    this.#consumed.add(entry.nonce)

    return true
  }

  async isConsumed(entry: DecisionNonceEntry): Promise<boolean> {
    return this.#consumed.has(entry.nonce)
  }

  get size(): number {
    return this.#consumed.size
  }
}

/**
 * Durable single-use tracking, backed by the PostgreSQL `ReplayStore`.
 *
 * Everything that is not an explicit `"consumed"` is a refusal. In particular `unavailable` — the
 * database being down — is a denial, never a permit.
 */
export class ReplayStoreDecisionNonceStore implements DecisionNonceStore {
  readonly #replayStore: ReplayStore

  constructor(replayStore: ReplayStore) {
    this.#replayStore = replayStore
  }

  async consume(entry: DecisionNonceEntry): Promise<boolean> {
    const outcome = await this.#replayStore.consume({
      tenantId: entry.tenantId,
      permitId: entry.permitId,
      nonce: entry.nonce,
      expiresAt: entry.expiresAt,
    })

    return outcome.outcome === "consumed"
  }

  async isConsumed(entry: DecisionNonceEntry): Promise<boolean> {
    return this.#replayStore.isConsumed({
      tenantId: entry.tenantId,
      permitId: entry.permitId,
      nonce: entry.nonce,
    })
  }
}
