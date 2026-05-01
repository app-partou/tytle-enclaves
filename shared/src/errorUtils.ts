/**
 * Extract a human-readable message from an unknown error.
 * Replaces `err: any` catch blocks with type-safe error handling.
 */
export function toErrorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === 'string') return err;
  return String(err);
}
