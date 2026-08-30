export class AgentEvidenceError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = new.target.name
  }
}

export class CanonicalizationError extends AgentEvidenceError {}
export class ParseError extends AgentEvidenceError {}
export class SchemaValidationError extends AgentEvidenceError {}
export class EvidenceValidationError extends AgentEvidenceError {}
export class TrustPolicyError extends AgentEvidenceError {}
export class SigningError extends AgentEvidenceError {}
