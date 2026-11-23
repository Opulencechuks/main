import type {
  ProofWorkerMessage,
  ProofWorkerResponse,
  WorkerMessageDispatchResult,
  WorkerOwnershipToken,
  WorkerStatus,
} from './proof.worker.types';
import { ProofWorkerLogger } from './proof-worker-logger';
import { validateCSPPolicy, isOriginAllowed, createCSPHeaders } from './csp-policy';
import {
  PROOF_MEMORY_ACCOUNTING_LIMITS,
  PROOF_MEMORY_BUFFER_CLASSES,
  ProofOperationMemoryAccountant,
  byteLengthOfProofWorkerValue,
  createProofOperationMemoryAccountant,
  type ProofBufferClassCounter,
  type ProofMemoryBufferClass,
  type ProofOperationMemoryReport,
  type ProofOperationMemoryStatus,
} from '../proofWorkerMemory';

export {
  PROOF_WORKER_PROTOCOL_VERSION,
  PROOF_MEMORY_ACCOUNTING_LIMITS,
  PROOF_MEMORY_BUFFER_CLASSES,
};
export type {
  WorkerProtocolVersionCheckResult,
  ProofBufferClassCounter,
  ProofMemoryBufferClass,
  ProofOperationMemoryReport,
  ProofOperationMemoryStatus,
};

const logger = new ProofWorkerLogger({ enabled: true });
const textEncoder = new TextEncoder();

export const PROOF_WORKER_DIAGNOSTIC_MAX_BYTES = PROOF_WORKER_MEMORY_LIMITS.maxDiagnosticBytes;

export type ProofWorkerDiagnosticLevel = 'debug' | 'info' | 'warn' | 'error';

export interface ProofWorkerDiagnosticInput {
  level?: ProofWorkerDiagnosticLevel;
  stage?: string;
  errorCode?: string;
  code?: string;
  id?: string;
  message?: string;
  context?: Record<string, unknown>;
}

export interface BoundedProofWorkerDiagnostic {
  level: ProofWorkerDiagnosticLevel;
  stage: string;
  errorCode?: string;
  code?: string;
  id?: string;
  message: string;
  context?: Record<string, unknown>;
  redactedWitnessValues: number;
  truncated: boolean;
  byteLength: number;
}

const WITNESS_KEY_PATTERN =
  /(witness|credential_?secret|nullifier_?secret|private_?inputs?|secret|seed|evidence|proof|assignment|nullifier|commitment)/i;

const SAFE_DIAGNOSTIC_KEYS = new Set([
  'stage',
  'errorCode',
  'code',
  'id',
  'level',
  'event',
  'status',
  'ok',
  'retryable',
  'duration_ms',
  'durationMs',
  'reason',
  'component',
]);

function utf8ByteLength(value: string): number {
  return textEncoder.encode(value).byteLength;
}

function truncateUtf8(value: string, maxBytes: number): string {
  if (maxBytes <= 0) return '';
  if (utf8ByteLength(value) <= maxBytes) return value;
  const suffix = '...[truncated]';
  const suffixBytes = utf8ByteLength(suffix);
  if (maxBytes <= suffixBytes) {
    let out = '';
    for (const ch of value) {
      if (utf8ByteLength(out + ch) > maxBytes) break;
      out += ch;
    }
    return out;
  }
  const budget = maxBytes - suffixBytes;
  let out = '';
  for (const ch of value) {
    if (utf8ByteLength(out + ch) > budget) break;
    out += ch;
  }
  return out + suffix;
}

function redactWitnessTokensInString(raw: string): { text: string; count: number } {
  let count = 0;
  let text = raw.replace(
    /\b(witness|credential_?secret|nullifier_?secret|private_?inputs?|secret|seed|evidence|proof|assignment)\s*([:=])\s*([^\s,;}\]]+)/gi,
    (_match, key: string, sep: string) => {
      count += 1;
      return `${key}${sep}[REDACTED:witness]`;
    },
  );
  text = text.replace(/\b0x[0-9a-fA-F]{16,}\b/g, () => {
    count += 1;
    return '[REDACTED:witness]';
  });
  text = text.replace(/\b[0-9a-fA-F]{32,}\b/g, () => {
    count += 1;
    return '[REDACTED:witness]';
  });
  text = text.replace(/\b\d{20,}\b/g, () => {
    count += 1;
    return '[REDACTED:witness]';
  });
  return { text, count };
}

function isWitnessShapedArray(value: unknown[]): boolean {
  if (value.length === 0) return false;
  if (value.some((item) => typeof item === 'bigint' || item instanceof ArrayBuffer || ArrayBuffer.isView(item))) {
    return true;
  }
  if (
    value.length >= 4 &&
    value.every(
      (item) =>
        typeof item === 'number' ||
        (typeof item === 'string' && (/^(0x)?[0-9a-fA-F]{16,}$/.test(item) || /^\d{20,}$/.test(item))),
    )
  ) {
    return true;
  }
  return false;
}

function redactWitnessValue(
  value: unknown,
  counter: { count: number },
  key?: string,
  depth = 0,
): unknown {
  if (key && !SAFE_DIAGNOSTIC_KEYS.has(key) && WITNESS_KEY_PATTERN.test(key)) {
    counter.count += 1;
    return '[REDACTED:witness]';
  }
  if (value === null || value === undefined) return value;
  if (typeof value === 'bigint' || value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
    counter.count += 1;
    return '[REDACTED:witness]';
  }
  if (typeof value === 'string') {
    const redacted = redactWitnessTokensInString(value);
    counter.count += redacted.count;
    return redacted.text;
  }
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (depth >= 6) return '[REDACTED:depth_limit]';
  if (Array.isArray(value)) {
    if (isWitnessShapedArray(value)) {
      counter.count += 1;
      return '[REDACTED:witness_array]';
    }
    return value.slice(0, 32).map((item) => redactWitnessValue(item, counter, undefined, depth + 1));
  }
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = redactWitnessValue(v, counter, k, depth + 1);
    }
    return out;
  }
  return String(value);
}

function normalizeIdentifier(value: string | undefined, fallback?: string): string | undefined {
  const trimmed = value?.trim();
  if (!trimmed) return fallback;
  return trimmed.slice(0, 128);
}

/**
 * Redacts witness-shaped values, preserves stable stage and error identifiers,
 * and caps the serialized UTF-8 payload byte length before forwarding a
 * proof-worker diagnostic to telemetry.
 */
export function boundProofWorkerDiagnostic(
  input: ProofWorkerDiagnosticInput,
  options?: { maxBytes?: number },
): BoundedProofWorkerDiagnostic {
  const requestedMax = options?.maxBytes ?? PROOF_WORKER_DIAGNOSTIC_MAX_BYTES;
  const maxBytes =
    Number.isFinite(requestedMax) && requestedMax > 0
      ? Math.floor(requestedMax)
      : PROOF_WORKER_DIAGNOSTIC_MAX_BYTES;

  const counter = { count: 0 };
  const level: ProofWorkerDiagnosticLevel = input.level ?? 'info';
  const stage = normalizeIdentifier(input.stage, 'unknown') ?? 'unknown';
  const errorCode = normalizeIdentifier(input.errorCode);
  const code = normalizeIdentifier(input.code);
  const id = normalizeIdentifier(input.id);

  const redactedMessage = redactWitnessTokensInString(input.message ?? '');
  counter.count += redactedMessage.count;
  let message = redactedMessage.text;

  let context: Record<string, unknown> | undefined;
  if (input.context && Object.keys(input.context).length > 0) {
    const witnessRedacted = redactWitnessValue(input.context, counter) as Record<string, unknown>;
    const scrubbed = scrubTelemetryFields(witnessRedacted);
    if (scrubbed.data && typeof scrubbed.data === 'object' && !Array.isArray(scrubbed.data)) {
      context = scrubbed.data as Record<string, unknown>;
    }
  }

  let truncated = false;
  const buildEnvelope = (
    msg: string,
    ctx: Record<string, unknown> | undefined,
    isTruncated: boolean,
    bytes: number,
  ): BoundedProofWorkerDiagnostic => {
    const env: BoundedProofWorkerDiagnostic = {
      level,
      stage,
      ...(errorCode ? { errorCode } : {}),
      ...(code ? { code } : {}),
      ...(id ? { id } : {}),
      message: msg,
      ...(ctx ? { context: ctx } : {}),
      redactedWitnessValues: counter.count,
      truncated: isTruncated,
      byteLength: bytes,
    };
    return env;
  };

  let envelope = buildEnvelope(message, context, false, 0);
  let serializedBytes = utf8ByteLength(JSON.stringify(envelope));
  envelope = buildEnvelope(message, context, false, serializedBytes);
  serializedBytes = utf8ByteLength(JSON.stringify(envelope));
  envelope.byteLength = serializedBytes;

  if (serializedBytes > maxBytes) {
    truncated = true;
    // First drop bulky context while retaining stable stage & error identifiers.
    context = undefined;
    envelope = buildEnvelope(message, undefined, true, 0);
    serializedBytes = utf8ByteLength(JSON.stringify(envelope));

    if (serializedBytes > maxBytes) {
      const overheadBytes = utf8ByteLength(
        JSON.stringify(buildEnvelope('', undefined, true, maxBytes)),
      );
      const messageBudget = Math.max(0, maxBytes - overheadBytes);
      message = truncateUtf8(message, messageBudget);
    }

    envelope = buildEnvelope(message, undefined, truncated, 0);
    serializedBytes = utf8ByteLength(JSON.stringify(envelope));
    envelope = buildEnvelope(message, undefined, truncated, serializedBytes);
    serializedBytes = utf8ByteLength(JSON.stringify(envelope));
    envelope.byteLength = serializedBytes;
  }

  return envelope;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Strictly validate a worker/main-thread protocol version without fallback parsing.
 * Rejects missing, non-integer, stringified, or mismatched versions fail-closed.
 */
export function validateWorkerProtocolVersion(
  receivedVersion: unknown,
  expectedVersion: number = PROOF_WORKER_PROTOCOL_VERSION
): WorkerProtocolVersionCheckResult {
  const isValidInteger =
    typeof receivedVersion === 'number' &&
    Number.isSafeInteger(receivedVersion) &&
    receivedVersion > 0;

  if (!isValidInteger) {
    return Object.freeze({
      compatible: false,
      code: 'PROTOCOL_VERSION_MISMATCH',
      expectedVersion,
      receivedVersion: null,
      reloadRequired: true,
      message: `Incompatible worker protocol version (expected ${expectedVersion}, received unknown). Reload required.`,
      privacySafe: true,
    });
  }

  if (receivedVersion !== expectedVersion) {
    return Object.freeze({
      compatible: false,
      code: 'PROTOCOL_VERSION_MISMATCH',
      expectedVersion,
      receivedVersion,
      reloadRequired: true,
      message: `Incompatible worker protocol version (expected ${expectedVersion}, received ${receivedVersion}). Reload required.`,
      privacySafe: true,
    });
  }

  return Object.freeze({
    compatible: true,
    protocolVersion: expectedVersion,
    reloadRequired: false,
  });
}

export function createProtocolMismatchResponse(
  check: Extract<WorkerProtocolVersionCheckResult, { compatible: false }>,
  id?: string
): ProofWorkerResponse {
  return {
    type: 'error',
    protocolVersion: check.expectedVersion,
    ...(id !== undefined ? { id } : {}),
    error: {
      code: check.code,
      message: check.message,
      privacySafe: true,
      reloadRequired: true,
    },
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Strictly validate a worker/main-thread protocol version without fallback parsing.
 * Rejects missing, non-integer, stringified, or mismatched versions fail-closed.
 */
export function validateWorkerProtocolVersion(
  receivedVersion: unknown,
  expectedVersion: number = PROOF_WORKER_PROTOCOL_VERSION
): WorkerProtocolVersionCheckResult {
  const isValidInteger =
    typeof receivedVersion === 'number' &&
    Number.isSafeInteger(receivedVersion) &&
    receivedVersion > 0;

  if (!isValidInteger) {
    return Object.freeze({
      compatible: false,
      code: 'PROTOCOL_VERSION_MISMATCH',
      expectedVersion,
      receivedVersion: null,
      reloadRequired: true,
      message: `Incompatible worker protocol version (expected ${expectedVersion}, received unknown). Reload required.`,
      privacySafe: true,
    });
  }

  if (receivedVersion !== expectedVersion) {
    return Object.freeze({
      compatible: false,
      code: 'PROTOCOL_VERSION_MISMATCH',
      expectedVersion,
      receivedVersion,
      reloadRequired: true,
      message: `Incompatible worker protocol version (expected ${expectedVersion}, received ${receivedVersion}). Reload required.`,
      privacySafe: true,
    });
  }

  return Object.freeze({
    compatible: true,
    protocolVersion: expectedVersion,
    reloadRequired: false,
  });
}

export function createProtocolMismatchResponse(
  check: Extract<WorkerProtocolVersionCheckResult, { compatible: false }>,
  id?: string
): ProofWorkerResponse {
  return {
    type: 'error',
    protocolVersion: check.expectedVersion,
    ...(id !== undefined ? { id } : {}),
    error: {
      code: check.code,
      message: check.message,
      privacySafe: true,
      reloadRequired: true,
    },
  };
}

/**
 * Coordinates browser proof worker lifecycle, CSP validation, and single-owner
 * operation generation tracking.
 *
 * Single ownership protocol:
 * - At most one active operation may hold ownership via `acquireOwnership()`.
 * - Each ownership acquisition, cancellation, or worker replacement/restart
 *   advances the monotonic `generation` counter.
 * - Incoming `progress` and proof (`success`/`error`) messages are dispatched
 *   through `handleWorkerMessage()`, which fails closed and rejects any message
 *   belonging to a cancelled, replaced, or unowned generation.
 */
export class ProofWorkerManager {
  // Preserve the currently active proof result to avoid losing state on unexpected messages
  private activeProofResult: ProofWorkerResponse | null = null;

  private worker: Worker | null = null;
  private cspConfig: ReturnType<typeof validateCSPPolicy>;
  private messageHandlers: Map<string, (response: ProofWorkerResponse) => void> = new Map();
  private progressHandlers: Map<string, (response: ProofWorkerResponse) => void> = new Map();
  private operationGenerations: Map<string, number> = new Map();
  private cancelledGenerations: Set<number> = new Set();
  private generation = 0;
  private activeOwner: WorkerOwnershipToken | null = null;
  private isInitialized = false;
  private readonly protocolVersion = PROOF_WORKER_PROTOCOL_VERSION;

  constructor(config?: Partial<ReturnType<typeof validateCSPPolicy>>) {
    this.cspConfig = validateCSPPolicy(config || {});
  }

  private trackOperationMemory(
    operationId: string,
    accountant: ProofOperationMemoryAccountant
  ): void {
    if (this.operationMemory.size >= PROOF_MEMORY_ACCOUNTING_LIMITS.maxTrackedOperations) {
      let evictKey: string | undefined;
      for (const [key, entry] of this.operationMemory.entries()) {
        if (entry.snapshot().status !== 'active') {
          evictKey = key;
          break;
        }
      }
      if (evictKey === undefined) {
        evictKey = this.operationMemory.keys().next().value;
      }
      if (evictKey !== undefined) {
        this.operationMemory.delete(evictKey);
      }
    }
    this.operationMemory.set(operationId, accountant);
  }

  async init(origin?: string): Promise<void> {

  }
    if (this.isInitialized) {
      logger.warn('Worker already initialized');
      return;
    }

    if (origin && !isOriginAllowed(origin, this.cspConfig)) {
      throw new Error(`Origin not allowed: ${origin}`);
    }

    try {
      this.isInitialized = true;
      logger.info('Worker manager initialized', { cspConfig: this.cspConfig });
    } catch (error) {
      logger.error('Failed to initialize worker manager', { error });
      throw error;
    }
  }

  /** Returns the current monotonic operation generation. */
  getGeneration(): number {
    return this.generation;
  }

  /** Returns a copy of the currently active ownership token, or null if idle. */
  getActiveOwner(): WorkerOwnershipToken | null {
    return this.activeOwner ? { ...this.activeOwner } : null;
  }

  /**
   * Acquires exclusive single-owner control of the worker for a proving or
   * verification operation. Advances the operation generation so messages from
   * any prior worker or operation cannot collide with the new owner.
   */
  acquireOwnership(operationId?: string): WorkerOwnershipToken {
    if (!this.isInitialized) {
      throw new Error('Worker manager not initialized');
    }

    if (this.activeOwner !== null) {
      throw new Error('Worker ownership already held by an active operation');
    }

    const id = operationId ?? `op_${Date.now()}_${Math.random().toString(36).slice(2, 11)}`;
    this.generation += 1;
    this.activeOwner = { generation: this.generation, operationId: id };
    this.operationGenerations.set(id, this.generation);
    return { ...this.activeOwner };
  }

  /**
   * Releases ownership if and only if the supplied token matches the active
   * owner's generation and operationId.
   */
  releaseOwnership(token: WorkerOwnershipToken): boolean {
    if (
      this.activeOwner === null ||
      this.activeOwner.generation !== token.generation ||
      this.activeOwner.operationId !== token.operationId
    ) {
      return false;
    }
    this.activeOwner = null;
    return true;
  }

  /**
   * Replaces the underlying worker instance, invalidating any active owner and
   * advancing the operation generation so stale messages from the replaced
   * worker are rejected.
   */
  replaceWorker(nextWorker: Worker | null = null): number {
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
    }

    if (this.activeOwner !== null) {
      this.cancelledGenerations.add(this.activeOwner.generation);
      this.activeOwner = null;
    } else if (this.generation > 0) {
      this.cancelledGenerations.add(this.generation);
    }

    this.generation += 1;
    this.worker = nextWorker;
    logger.info('Worker replaced', { generation: this.generation });
    return this.generation;
  }

  /**
   * Restarts the worker by replacing it and advancing the operation generation.
   */
  restartWorker(nextWorker: Worker | null = null): number {
    return this.replaceWorker(nextWorker);
  }

  /**
   * Validates and dispatches an incoming worker response against the single
   * ownership protocol. Rejects stale progress and proof messages from
   * cancelled, replaced, or unowned generations.
   */
  handleWorkerMessage(response: ProofWorkerResponse): WorkerMessageDispatchResult {
    if (!this.isInitialized) {
      return {
        accepted: false,
        reason: 'not_initialized',
        expectedGeneration: this.generation,
        receivedGeneration: response.generation,
      };
    }

    const receivedGeneration = response.generation;

    if (receivedGeneration !== undefined && this.cancelledGenerations.has(receivedGeneration)) {
      return {
        accepted: false,
        reason: 'cancelled',
        expectedGeneration: this.generation,
        receivedGeneration,
      };
    }

    if (this.activeOwner !== null) {
      if (receivedGeneration === undefined || receivedGeneration !== this.activeOwner.generation) {
        return {
          accepted: false,
          reason: 'stale_generation',
          expectedGeneration: this.activeOwner.generation,
          receivedGeneration,
        };
      }

      if (!response.id || response.id !== this.activeOwner.operationId) {
        return {
          accepted: false,
          reason: 'unowned_operation',
          expectedGeneration: this.activeOwner.generation,
          receivedGeneration,
        };
      }
    } else {
      if (receivedGeneration !== undefined && receivedGeneration !== this.generation) {
        return {
          accepted: false,
          reason: 'stale_generation',
          expectedGeneration: this.generation,
          receivedGeneration,
        };
      }

      const recordedGeneration = response.id ? this.operationGenerations.get(response.id) : undefined;
      if (recordedGeneration === undefined) {
        return {
          accepted: false,
          reason: 'unowned_operation',
          expectedGeneration: this.generation,
          receivedGeneration,
        };
      }

      if (this.cancelledGenerations.has(recordedGeneration)) {
        return {
          accepted: false,
          reason: 'cancelled',
          expectedGeneration: this.generation,
          receivedGeneration,
        };
      }

      if (recordedGeneration !== this.generation) {
        return {
          accepted: false,
          reason: 'stale_generation',
          expectedGeneration: this.generation,
          receivedGeneration,
        };
      }
    }

    const operationId = response.id ?? '';
    if (response.type === 'progress') {
      const progressHandler = this.progressHandlers.get(operationId);
      if (progressHandler) {
        progressHandler(response);
      }
      return { accepted: true, generation: this.generation, operationId };
    }

    if (response.type === 'success' || response.type === 'error') {
      const handler = this.messageHandlers.get(operationId);
      if (handler) {
        handler(response);
      }
      this.progressHandlers.delete(operationId);
      this.operationGenerations.delete(operationId);
      if (this.activeOwner && this.activeOwner.operationId === operationId) {
        this.activeOwner = null;
      }
      return { accepted: true, generation: this.generation, operationId };
    }

    return { accepted: true, generation: this.generation, operationId };
  }

  async verifyProof(
    evidence: string,
    proof: string,
    contract: string,
    timeout?: number,
    onProgress?: (response: ProofWorkerResponse) => void
  ): Promise<ProofWorkerResponse> {
    if (!this.isInitialized) {
      throw new Error('Worker manager not initialized');
    }

    const messageId = `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const operationGeneration = this.generation;
    this.operationGenerations.set(messageId, operationGeneration);

    if (onProgress) {
      this.progressHandlers.set(messageId, onProgress);
    }

    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        this.messageHandlers.delete(messageId);
        this.progressHandlers.delete(messageId);
        this.operationGenerations.delete(messageId);
        reject(new Error('Verification timed out'));
      }, timeout || this.cspConfig.maxExecutionTimeMs);

      this.messageHandlers.set(messageId, (response) => {
        clearTimeout(timeoutId);
        this.messageHandlers.delete(messageId);
        this.progressHandlers.delete(messageId);
        this.operationGenerations.delete(messageId);
        resolve(response);
      });

      const message: ProofWorkerMessage = {
        protocolVersion: this.protocolVersion,
        type: 'verify',
        payload: {
          evidence,
          proof,
          contract,
          timeout,
        },
        id: messageId,
        generation: operationGeneration,
      };

      logger.info('Sending verify message', { id: messageId });
      this.worker?.postMessage(message);
    });
  }

  /** Registers a transient buffer so it is wiped when the session completes or is reused. */
  trackBuffer<T extends ArrayBuffer | ArrayBufferView>(buffer: T): T {
    return this.bufferLedger.track(buffer);
  }

  /** Releases a buffer once it has been transferred or exported. */
  releaseBuffer(buffer: ArrayBuffer | ArrayBufferView): void {
    this.bufferLedger.release(buffer);
  }

  async cancelProof(): Promise<void> {
    if (!this.isInitialized) {
      throw new Error('Worker manager not initialized');
    }

    const messageId = `cancel_${Date.now()}`;

    if (this.activeOwner !== null) {
      this.cancelledGenerations.add(this.activeOwner.generation);
      this.activeOwner = null;
      this.generation += 1;
    } else if (this.operationGenerations.size > 0 || this.generation > 0) {
      this.cancelledGenerations.add(this.generation);
      this.generation += 1;
    }

    const message: ProofWorkerMessage = {
      protocolVersion: this.protocolVersion,
      type: 'cancel',
      id: messageId,
      generation: this.generation,
    };

    logger.info('Sending cancel message', { id: messageId });
    this.worker?.postMessage(message);
  }

  getProtocolVersion(): number {
    return this.protocolVersion;
  }

  /**
   * Validate an incoming worker message's protocol version before accepting any
   * transferred buffers or parsing payload fields. Returns a clear reload-required
   * error response on mismatch and settles any matching pending request.
   */
  handleWorkerMessage(
    rawMessage: unknown,
    acceptBuffers?: () => readonly ArrayBuffer[]
  ): ProofWorkerResponse {
    const candidate = isRecord(rawMessage) ? rawMessage : null;
    const id = candidate && typeof candidate.id === 'string' ? candidate.id : undefined;
    const check = validateWorkerProtocolVersion(
      candidate ? candidate.protocolVersion : undefined,
      this.protocolVersion
    );

    if (!check.compatible) {
      logger.warn('Rejected incompatible worker protocol version', {
        expectedVersion: check.expectedVersion,
        receivedVersion: check.receivedVersion,
        reloadRequired: true,
      });
      const mismatchResponse = createProtocolMismatchResponse(check, id);
      if (id !== undefined) {
        const handler = this.messageHandlers.get(id);
        handler?.(mismatchResponse);
      }
      return mismatchResponse;
    }

    // Protocol version verified: safe to accept transferred buffers and dispatch.
    acceptBuffers?.();
    const response = candidate as unknown as ProofWorkerResponse;
    if (id !== undefined) {
      const handler = this.messageHandlers.get(id);
      handler?.(response);
    }
    return response;
  }

  getProtocolVersion(): number {
    return this.protocolVersion;
  }

  /**
   * Validate an incoming worker message's protocol version before accepting any
   * transferred buffers or parsing payload fields. Returns a clear reload-required
   * error response on mismatch and settles any matching pending request.
   */
  handleWorkerMessage(
    rawMessage: unknown,
    acceptBuffers?: () => readonly ArrayBuffer[]
  ): ProofWorkerResponse {
    const candidate = isRecord(rawMessage) ? rawMessage : null;
    const id = candidate && typeof candidate.id === 'string' ? candidate.id : undefined;
    const check = validateWorkerProtocolVersion(
      candidate ? candidate.protocolVersion : undefined,
      this.protocolVersion
    );

    if (!check.compatible) {
      logger.warn('Rejected incompatible worker protocol version', {
        expectedVersion: check.expectedVersion,
        receivedVersion: check.receivedVersion,
        reloadRequired: true,
      });
      const mismatchResponse = createProtocolMismatchResponse(check, id);
      if (id !== undefined) {
        const handler = this.messageHandlers.get(id);
        handler?.(mismatchResponse);
      }
      return mismatchResponse;
    }

    // Protocol version verified: safe to accept transferred buffers and dispatch.
    const acceptedBuffers = acceptBuffers?.() ?? [];
    if (id !== undefined && acceptedBuffers.length > 0) {
      const accountant = this.operationMemory.get(id);
      if (accountant) {
        const transferredBytes = acceptedBuffers.reduce(
          (total, buffer) => total + buffer.byteLength,
          0
        );
        accountant.allocate('proof', transferredBytes);
      }
    }
    const response = candidate as unknown as ProofWorkerResponse;
    if (id !== undefined) {
      const handler = this.messageHandlers.get(id);
      handler?.(response);
    }
    return response;
  }

  /**
   * Returns a frozen, privacy-safe per-operation buffer accounting snapshot.
   * Counters reflect tracked operation buffer classes only and do not claim
   * browser-wide heap or OS-level memory precision.
   */
  getOperationMemoryReport(operationId: string): ProofOperationMemoryReport | undefined {
    return this.operationMemory.get(operationId)?.snapshot();
  }

  /**
   * Returns a bounded snapshot of tracked per-operation memory reports.
   */
  getMemoryAccountingSnapshot(): readonly ProofOperationMemoryReport[] {
    return Object.freeze(
      Array.from(this.operationMemory.values(), (accountant) => accountant.snapshot())
    );
  }

  getStatus(): WorkerStatus {
    return {
      isRunning: false,
      currentTaskId: undefined,
      memoryUsage: undefined,
    };
  }

  getResourceAdmissionDecision(
    options: Partial<ProofWorkerResourceAdmissionInput> = {}
  ): ProofWorkerResourceAdmissionDecision {
    const nav =
      typeof navigator !== 'undefined'
        ? (navigator as Navigator & { deviceMemory?: number })
        : undefined;
    const crossOriginIsolated =
      options.crossOriginIsolated ??
      (typeof globalThis.crossOriginIsolated === 'boolean'
        ? globalThis.crossOriginIsolated
        : false);
    const hardwareConcurrency =
      options.hardwareConcurrency !== undefined
        ? options.hardwareConcurrency
        : nav?.hardwareConcurrency ?? 1;
    const deviceMemoryGB =
      options.deviceMemoryGB !== undefined
        ? options.deviceMemoryGB
        : typeof nav?.deviceMemory === 'number'
          ? nav.deviceMemory
          : null;

    return evaluateProofWorkerResourceAdmission({
      usage: options.usage,
      maxMemoryMB: options.maxMemoryMB ?? this.cspConfig.maxMemoryMB,
      deviceMemoryGB,
      crossOriginIsolated,
      hardwareConcurrency,
      activeTasks: options.activeTasks ?? this.messageHandlers.size,
      maxConcurrentTasks: options.maxConcurrentTasks ?? 1,
    });
  }

  getCSPHeaders(): Record<string, string> {
    return createCSPHeaders(this.cspConfig);
  }

  forwardDiagnosticToTelemetry(
    diagnostic: ProofWorkerDiagnosticInput,
    options?: { maxBytes?: number; emit?: typeof emitScrubbedTelemetry },
  ): BoundedProofWorkerDiagnostic {
    const bounded = boundProofWorkerDiagnostic(diagnostic, { maxBytes: options?.maxBytes });
    const sink = options?.emit ?? emitScrubbedTelemetry;
    sink(bounded.level, 'proof_worker.diagnostic', { ...bounded });
    return bounded;
  }

  destroy(): void {
    this.bufferLedger.clear();
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
    }
    if (this.activeOwner !== null) {
      this.cancelledGenerations.add(this.activeOwner.generation);
      this.activeOwner = null;
    }
    this.generation += 1;
    this.messageHandlers.clear();
    this.progressHandlers.clear();
    this.operationGenerations.clear();
    this.isInitialized = false;
    logger.info('Worker manager destroyed');
  }
}
