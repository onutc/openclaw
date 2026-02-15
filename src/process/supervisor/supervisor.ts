import crypto from "node:crypto";
import type {
  ManagedRun,
  ProcessSupervisor,
  RunExit,
  RunRecord,
  SpawnInput,
  TerminationReason,
} from "./types.js";
import { getShellConfig } from "../../agents/shell-utils.js";
import { createSubsystemLogger } from "../../logging/subsystem.js";
import { createChildAdapter } from "./adapters/child.js";
import { createPtyAdapter } from "./adapters/pty.js";
import { createRunRegistry } from "./registry.js";

const log = createSubsystemLogger("process/supervisor");

type ActiveRun = {
  run: ManagedRun;
  scopeKey?: string;
};

function clampTimeout(value?: number): number | undefined {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    return undefined;
  }
  return Math.max(1, Math.floor(value));
}

function isTimeoutReason(reason: TerminationReason) {
  return reason === "overall-timeout" || reason === "no-output-timeout";
}

export function createProcessSupervisor(): ProcessSupervisor {
  const registry = createRunRegistry();
  const active = new Map<string, ActiveRun>();

  const cancel = (runId: string, reason: TerminationReason = "manual-cancel") => {
    const current = active.get(runId);
    if (!current) {
      return;
    }
    registry.updateState(runId, "exiting", {
      terminationReason: reason,
    });
    current.run.cancel(reason);
  };

  const cancelScope = (scopeKey: string, reason: TerminationReason = "manual-cancel") => {
    if (!scopeKey.trim()) {
      return;
    }
    for (const [runId, run] of active.entries()) {
      if (run.scopeKey !== scopeKey) {
        continue;
      }
      cancel(runId, reason);
    }
  };

  const spawn = async (input: SpawnInput): Promise<ManagedRun> => {
    const runId = input.runId?.trim() || crypto.randomUUID();
    if (input.replaceExistingScope && input.scopeKey?.trim()) {
      cancelScope(input.scopeKey, "manual-cancel");
    }
    const startedAtMs = Date.now();
    const record: RunRecord = {
      runId,
      sessionId: input.sessionId,
      backendId: input.backendId,
      scopeKey: input.scopeKey?.trim() || undefined,
      state: "starting",
      startedAtMs,
      lastOutputAtMs: startedAtMs,
      createdAtMs: startedAtMs,
      updatedAtMs: startedAtMs,
    };
    registry.add(record);

    let forcedReason: TerminationReason | null = null;
    let settled = false;
    let stdout = "";
    let stderr = "";
    let timeoutTimer: NodeJS.Timeout | null = null;
    let noOutputTimer: NodeJS.Timeout | null = null;

    const overallTimeoutMs = clampTimeout(input.timeoutMs);
    const noOutputTimeoutMs = clampTimeout(input.noOutputTimeoutMs);

    const setForcedReason = (reason: TerminationReason) => {
      if (forcedReason) {
        return;
      }
      forcedReason = reason;
      registry.updateState(runId, "exiting", { terminationReason: reason });
    };

    const touchOutput = () => {
      registry.touchOutput(runId);
      if (!noOutputTimeoutMs || settled) {
        return;
      }
      if (noOutputTimer) {
        clearTimeout(noOutputTimer);
      }
      noOutputTimer = setTimeout(() => {
        setForcedReason("no-output-timeout");
        active.get(runId)?.run.cancel("no-output-timeout");
      }, noOutputTimeoutMs);
    };

    try {
      const adapter =
        input.mode === "pty"
          ? await (async () => {
              const { shell, args: shellArgs } = getShellConfig();
              if (input.argv.length === 0) {
                throw new Error("spawn argv cannot be empty");
              }
              const command = [input.argv[0], ...input.argv.slice(1)].join(" ");
              return await createPtyAdapter({
                shell,
                args: [...shellArgs, command],
                cwd: input.cwd,
                env: input.env,
              });
            })()
          : await createChildAdapter({
              argv: input.argv,
              cwd: input.cwd,
              env: input.env,
              windowsVerbatimArguments: input.windowsVerbatimArguments,
              input: input.input,
              stdinMode: input.stdinMode,
            });

      registry.updateState(runId, "running", { pid: adapter.pid });

      const clearTimers = () => {
        if (timeoutTimer) {
          clearTimeout(timeoutTimer);
          timeoutTimer = null;
        }
        if (noOutputTimer) {
          clearTimeout(noOutputTimer);
          noOutputTimer = null;
        }
      };

      if (overallTimeoutMs) {
        timeoutTimer = setTimeout(() => {
          setForcedReason("overall-timeout");
          active.get(runId)?.run.cancel("overall-timeout");
        }, overallTimeoutMs);
      }
      if (noOutputTimeoutMs) {
        noOutputTimer = setTimeout(() => {
          setForcedReason("no-output-timeout");
          active.get(runId)?.run.cancel("no-output-timeout");
        }, noOutputTimeoutMs);
      }

      adapter.onStdout((chunk) => {
        stdout += chunk;
        input.onStdout?.(chunk);
        touchOutput();
      });
      adapter.onStderr((chunk) => {
        stderr += chunk;
        input.onStderr?.(chunk);
        touchOutput();
      });

      const waitPromise = (async (): Promise<RunExit> => {
        const result = await adapter.wait();
        if (settled) {
          return {
            reason: forcedReason ?? "exit",
            exitCode: result.code,
            exitSignal: result.signal,
            durationMs: Date.now() - startedAtMs,
            stdout,
            stderr,
            timedOut: isTimeoutReason(forcedReason ?? "exit"),
            noOutputTimedOut: forcedReason === "no-output-timeout",
          };
        }
        settled = true;
        clearTimers();
        adapter.dispose();
        active.delete(runId);

        const reason: TerminationReason =
          forcedReason ?? (result.signal != null ? ("signal" as const) : ("exit" as const));
        const exit: RunExit = {
          reason,
          exitCode: result.code,
          exitSignal: result.signal,
          durationMs: Date.now() - startedAtMs,
          stdout,
          stderr,
          timedOut: isTimeoutReason(forcedReason ?? reason),
          noOutputTimedOut: forcedReason === "no-output-timeout",
        };
        registry.finalize(runId, {
          reason: exit.reason,
          exitCode: exit.exitCode,
          exitSignal: exit.exitSignal,
        });
        return exit;
      })().catch((err) => {
        if (!settled) {
          settled = true;
          clearTimers();
          active.delete(runId);
          adapter.dispose();
          registry.finalize(runId, {
            reason: "spawn-error",
            exitCode: null,
            exitSignal: null,
          });
        }
        throw err;
      });

      const managedRun: ManagedRun = {
        runId,
        pid: adapter.pid,
        startedAtMs,
        stdin: adapter.stdin,
        wait: async () => await waitPromise,
        cancel: (reason = "manual-cancel") => {
          setForcedReason(reason);
          adapter.kill("SIGKILL");
        },
      };

      active.set(runId, {
        run: managedRun,
        scopeKey: input.scopeKey?.trim() || undefined,
      });
      return managedRun;
    } catch (err) {
      registry.finalize(runId, {
        reason: "spawn-error",
        exitCode: null,
        exitSignal: null,
      });
      log.warn(`spawn failed: runId=${runId} reason=${String(err)}`);
      throw err;
    }
  };

  return {
    spawn,
    cancel,
    cancelScope,
    reconcileOrphans: async () => {
      // The current implementation keeps ownership in memory only.
      // Durable reconciliation will be added once persistent registry wiring lands.
    },
    getRecord: (runId: string) => registry.get(runId),
  };
}
