import type { ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { spawnWithFallbackMock, killProcessTreeMock } = vi.hoisted(() => ({
  spawnWithFallbackMock: vi.fn(),
  killProcessTreeMock: vi.fn(),
}));

vi.mock("../../spawn-utils.js", () => ({
  spawnWithFallback: (...args: unknown[]) => spawnWithFallbackMock(...args),
}));

vi.mock("../../kill-tree.js", () => ({
  killProcessTree: (...args: unknown[]) => killProcessTreeMock(...args),
}));

function createStubChild(pid = 1234) {
  const child = new EventEmitter() as ChildProcess;
  child.stdin = new PassThrough() as ChildProcess["stdin"];
  child.stdout = new PassThrough() as ChildProcess["stdout"];
  child.stderr = new PassThrough() as ChildProcess["stderr"];
  child.pid = pid;
  child.killed = false;
  const killMock = vi.fn(() => true);
  child.kill = killMock as ChildProcess["kill"];
  return { child, killMock };
}

describe("createChildAdapter", () => {
  beforeEach(() => {
    spawnWithFallbackMock.mockReset();
    killProcessTreeMock.mockReset();
  });

  it("uses process-tree kill for default SIGKILL", async () => {
    const { child, killMock } = createStubChild(4321);
    spawnWithFallbackMock.mockResolvedValue({
      child,
      usedFallback: false,
    });
    const { createChildAdapter } = await import("./child.js");
    const adapter = await createChildAdapter({
      argv: ["node", "-e", "setTimeout(() => {}, 1000)"],
      stdinMode: "pipe-open",
    });

    const spawnArgs = spawnWithFallbackMock.mock.calls[0]?.[0] as {
      options?: { detached?: boolean };
      fallbacks?: Array<{ options?: { detached?: boolean } }>;
    };
    expect(spawnArgs.options?.detached).toBe(true);
    expect(spawnArgs.fallbacks?.[0]?.options?.detached).toBe(false);

    adapter.kill();

    expect(killProcessTreeMock).toHaveBeenCalledWith(4321);
    expect(killMock).not.toHaveBeenCalled();
  });

  it("uses direct child.kill for non-SIGKILL signals", async () => {
    const { child, killMock } = createStubChild(7654);
    spawnWithFallbackMock.mockResolvedValue({
      child,
      usedFallback: false,
    });
    const { createChildAdapter } = await import("./child.js");
    const adapter = await createChildAdapter({
      argv: ["node", "-e", "setTimeout(() => {}, 1000)"],
      stdinMode: "pipe-open",
    });

    adapter.kill("SIGTERM");

    expect(killProcessTreeMock).not.toHaveBeenCalled();
    expect(killMock).toHaveBeenCalledWith("SIGTERM");
  });
});
