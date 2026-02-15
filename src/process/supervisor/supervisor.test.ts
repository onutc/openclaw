import { describe, expect, it } from "vitest";
import { createProcessSupervisor } from "./supervisor.js";

describe("process supervisor", () => {
  it("spawns child runs and captures output", async () => {
    const supervisor = createProcessSupervisor();
    const run = await supervisor.spawn({
      sessionId: "s1",
      backendId: "test",
      mode: "child",
      argv: [process.execPath, "-e", 'process.stdout.write("ok")'],
      timeoutMs: 2_000,
      stdinMode: "pipe-closed",
    });
    const exit = await run.wait();
    expect(exit.reason).toBe("exit");
    expect(exit.exitCode).toBe(0);
    expect(exit.stdout).toBe("ok");
  });

  it("enforces no-output timeout for silent processes", async () => {
    const supervisor = createProcessSupervisor();
    const run = await supervisor.spawn({
      sessionId: "s1",
      backendId: "test",
      mode: "child",
      argv: [process.execPath, "-e", "setTimeout(() => {}, 10_000)"],
      timeoutMs: 5_000,
      noOutputTimeoutMs: 200,
      stdinMode: "pipe-closed",
    });
    const exit = await run.wait();
    expect(exit.reason).toBe("no-output-timeout");
    expect(exit.noOutputTimedOut).toBe(true);
    expect(exit.timedOut).toBe(true);
  });

  it("cancels prior scoped run when replaceExistingScope is enabled", async () => {
    const supervisor = createProcessSupervisor();
    const first = await supervisor.spawn({
      sessionId: "s1",
      backendId: "test",
      scopeKey: "scope:a",
      mode: "child",
      argv: [process.execPath, "-e", "setTimeout(() => {}, 10_000)"],
      timeoutMs: 10_000,
      stdinMode: "pipe-open",
    });

    const second = await supervisor.spawn({
      sessionId: "s1",
      backendId: "test",
      scopeKey: "scope:a",
      replaceExistingScope: true,
      mode: "child",
      argv: [process.execPath, "-e", 'process.stdout.write("new")'],
      timeoutMs: 2_000,
      stdinMode: "pipe-closed",
    });

    const firstExit = await first.wait();
    const secondExit = await second.wait();
    expect(firstExit.reason === "manual-cancel" || firstExit.reason === "signal").toBe(true);
    expect(secondExit.reason).toBe("exit");
    expect(secondExit.stdout).toBe("new");
  });
});
