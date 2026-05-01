/**
 * Structured JSON logger for enclave handlers.
 *
 * Outputs one JSON line per log entry to stdout (info/warn) or stderr (error).
 * Compatible with CloudWatch JSON structured log parsing.
 */

export interface Logger {
  info(msg: string, fields?: Record<string, unknown>): void;
  warn(msg: string, fields?: Record<string, unknown>): void;
  error(msg: string, fields?: Record<string, unknown>): void;
}

export function createLogger(enclaveName: string): Logger {
  const log = (level: string, stream: 'stdout' | 'stderr', msg: string, fields?: Record<string, unknown>) => {
    const entry = {
      timestamp: new Date().toISOString(),
      level,
      enclave: enclaveName,
      message: msg,
      ...fields,
    };
    const line = JSON.stringify(entry);
    if (stream === 'stderr') {
      process.stderr.write(line + '\n');
    } else {
      process.stdout.write(line + '\n');
    }
  };

  return {
    info: (msg, fields) => log('INFO', 'stdout', msg, fields),
    warn: (msg, fields) => log('WARN', 'stdout', msg, fields),
    error: (msg, fields) => log('ERROR', 'stderr', msg, fields),
  };
}
