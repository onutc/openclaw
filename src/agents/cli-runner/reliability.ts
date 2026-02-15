import path from "node:path";
import type { CliBackendConfig } from "../../config/types.js";

const DEFAULT_MIN_TIMEOUT_MS = 1_000;
const DEFAULT_RESUME_WATCHDOG = {
  noOutputTimeoutRatio: 0.3,
  minMs: 60_000,
  maxMs: 180_000,
};
const DEFAULT_FRESH_WATCHDOG = {
  noOutputTimeoutRatio: 0.8,
  minMs: 180_000,
  maxMs: 600_000,
};

function pickWatchdogProfile(
  backend: CliBackendConfig,
  useResume: boolean,
): {
  noOutputTimeoutMs?: number;
  noOutputTimeoutRatio: number;
  minMs: number;
  maxMs: number;
} {
  const defaults = useResume ? DEFAULT_RESUME_WATCHDOG : DEFAULT_FRESH_WATCHDOG;
  const configured = useResume
    ? backend.reliability?.watchdog?.resume
    : backend.reliability?.watchdog?.fresh;

  const ratio = (() => {
    const value = configured?.noOutputTimeoutRatio;
    if (typeof value !== "number" || !Number.isFinite(value)) {
      return defaults.noOutputTimeoutRatio;
    }
    return Math.max(0.05, Math.min(0.95, value));
  })();
  const minMs = (() => {
    const value = configured?.minMs;
    if (typeof value !== "number" || !Number.isFinite(value)) {
      return defaults.minMs;
    }
    return Math.max(DEFAULT_MIN_TIMEOUT_MS, Math.floor(value));
  })();
  const maxMs = (() => {
    const value = configured?.maxMs;
    if (typeof value !== "number" || !Number.isFinite(value)) {
      return defaults.maxMs;
    }
    return Math.max(DEFAULT_MIN_TIMEOUT_MS, Math.floor(value));
  })();

  return {
    noOutputTimeoutMs:
      typeof configured?.noOutputTimeoutMs === "number" &&
      Number.isFinite(configured.noOutputTimeoutMs)
        ? Math.max(DEFAULT_MIN_TIMEOUT_MS, Math.floor(configured.noOutputTimeoutMs))
        : undefined,
    noOutputTimeoutRatio: ratio,
    minMs: Math.min(minMs, maxMs),
    maxMs: Math.max(minMs, maxMs),
  };
}

export function resolveCliNoOutputTimeoutMs(params: {
  backend: CliBackendConfig;
  timeoutMs: number;
  useResume: boolean;
}): number {
  const profile = pickWatchdogProfile(params.backend, params.useResume);
  // Keep watchdog below global timeout in normal cases.
  const cap = Math.max(DEFAULT_MIN_TIMEOUT_MS, params.timeoutMs - 1_000);
  if (profile.noOutputTimeoutMs !== undefined) {
    return Math.min(profile.noOutputTimeoutMs, cap);
  }
  const computed = Math.floor(params.timeoutMs * profile.noOutputTimeoutRatio);
  const bounded = Math.min(profile.maxMs, Math.max(profile.minMs, computed));
  return Math.min(bounded, cap);
}

export function buildCliSupervisorScopeKey(params: {
  backend: CliBackendConfig;
  backendId: string;
  cliSessionId?: string;
}): string | undefined {
  const commandToken = path
    .basename(params.backend.command ?? "")
    .trim()
    .toLowerCase();
  const backendToken = params.backendId.trim().toLowerCase();
  const sessionToken = params.cliSessionId?.trim();
  if (!sessionToken) {
    return undefined;
  }
  return `cli:${backendToken}:${commandToken}:${sessionToken}`;
}
