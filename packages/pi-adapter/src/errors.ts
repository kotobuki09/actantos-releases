export class GuardedAccessDenied extends Error {
  readonly name = "GuardedAccessDenied"
  readonly reasonCode: string
  readonly decisionId?: string
  readonly requestId?: string

  constructor(
    reasonCode: string,
    message = `guarded access denied (${reasonCode})`,
    decisionId?: string,
    requestId?: string,
  ) {
    super(message)
    this.reasonCode = reasonCode
    if (decisionId !== undefined) {
      this.decisionId = decisionId
    }
    if (requestId !== undefined) {
      this.requestId = requestId
    }
  }
}

export class ApprovalRequired extends Error {
  readonly name = "ApprovalRequired"
  readonly approvalId: string
  readonly priorDecisionId: string
  readonly reasonCode: string
  readonly decisionId?: string
  readonly requestId?: string

  constructor(
    approvalId: string,
    priorDecisionId = approvalId,
    reasonCode = "approval_required",
    message = `approval required (${approvalId})`,
    decisionId?: string,
    requestId?: string,
  ) {
    super(message)
    this.approvalId = approvalId
    this.priorDecisionId = priorDecisionId
    this.reasonCode = reasonCode
    if (decisionId !== undefined) {
      this.decisionId = decisionId
    }
    if (requestId !== undefined) {
      this.requestId = requestId
    }
  }
}
