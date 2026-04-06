/** Actions that can be taken when PII is detected */
export type PIIAction = 'block' | 'redact' | 'warn';

/** A single PII match found by a detector */
export interface PIIMatch {
  /** PII type identifier (e.g., 'email', 'ssn', 'credit_card') */
  type: string;
  /** The matched text — ONLY used during detection, discarded after redaction */
  value: string;
  /** Detection confidence 0.0-1.0 */
  confidence: number;
  /** Start index in the scanned string */
  start: number;
  /** End index (exclusive) in the scanned string */
  end: number;
}

/** Context passed to detectors */
export interface DetectionContext {
  /** The direction of the message being scanned */
  direction: 'request' | 'response';
  /** Server name from config */
  server: string;
}

/** Pluggable PII detector interface */
export interface PIIDetector {
  /** Unique name for this detector */
  name: string;
  /** Detect PII in a string, returning all matches */
  detect(content: string, ctx: DetectionContext): PIIMatch[];
}

/** Per-type directional action config */
export interface PIITypeActions {
  request: PIIAction;
  response: PIIAction;
}

/** Custom PII type definition from config */
export interface CustomPIIType {
  label: string;
  patterns: Array<{ regex: string }>;
  actions: PIITypeActions;
}

/** A PII match with the value stripped — safe for logging and metadata */
export interface PIIMatchSafe {
  type: string;
  confidence: number;
  start: number;
  end: number;
}

/** Result of scanning a structured object */
export interface ScanResult {
  /** All PII matches found, with value stripped (safe for audit/metadata) */
  matches: Array<PIIMatchSafe & { path: string }>;
  /** The object with matched spans redacted (new object, original not mutated) */
  redacted: unknown;
}
