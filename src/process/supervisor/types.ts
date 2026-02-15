import type { SessionStdin } from "../../agents/bash-process-registry.js";

export type RunState = "starting" | "running" | "exiting" | "exited";

export type TerminationReason =
  | "manual-cancel"
  | "overall-timeout"
  | "no-output-timeout"
  | "spawn-error"
  | "signal"
  | "exit";

export type RunRecord = {
  runId: string;
  sessionId: string;
  backendId: string;
  scopeKey?: string;
  pid?: number;
  processGroupId?: number;
  startedAtMs: number;
  lastOutputAtMs: number;
  createdAtMs: number;
  updatedAtMs: number;
  state: RunState;
  terminationReason?: TerminationReason;
  exitCode?: number | null;
  exitSignal?: NodeJS.Signals | number | null;
};

export type RunExit = {
  reason: TerminationReason;
  exitCode: number | null;
  exitSignal: NodeJS.Signals | number | null;
  durationMs: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  noOutputTimedOut: boolean;
};

export type ManagedRun = {
  runId: string;
  pid?: number;
  startedAtMs: number;
  stdin?: SessionStdin;
  wait: () => Promise<RunExit>;
  cancel: (reason?: TerminationReason) => void;
};

export type SpawnMode = "child" | "pty";

export type SpawnInput = {
  runId?: string;
  sessionId: string;
  backendId: string;
  scopeKey?: string;
  replaceExistingScope?: boolean;
  mode: SpawnMode;
  argv: string[];
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  windowsVerbatimArguments?: boolean;
  timeoutMs?: number;
  noOutputTimeoutMs?: number;
  input?: string;
  stdinMode?: "inherit" | "pipe-open" | "pipe-closed";
  onStdout?: (chunk: string) => void;
  onStderr?: (chunk: string) => void;
};

export interface ProcessSupervisor {
  spawn(input: SpawnInput): Promise<ManagedRun>;
  cancel(runId: string, reason?: TerminationReason): void;
  cancelScope(scopeKey: string, reason?: TerminationReason): void;
  reconcileOrphans(): Promise<void>;
  getRecord(runId: string): RunRecord | undefined;
}
