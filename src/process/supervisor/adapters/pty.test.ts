import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { spawnMock, ptyKillMock } = vi.hoisted(() => ({
  spawnMock: vi.fn(),
  ptyKillMock: vi.fn(),
}));

vi.mock("@lydell/node-pty", () => ({
  spawn: (...args: unknown[]) => spawnMock(...args),
}));

function createStubPty(pid = 1234) {
  return {
    pid,
    write: vi.fn(),
    onData: vi.fn(() => ({ dispose: vi.fn() })),
    onExit: vi.fn(() => ({ dispose: vi.fn() })),
    kill: (signal?: string) => ptyKillMock(signal),
  };
}

describe("createPtyAdapter", () => {
  beforeEach(() => {
    spawnMock.mockReset();
    ptyKillMock.mockReset();
  });

  afterEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  it("forwards explicit signals to node-pty kill", async () => {
    spawnMock.mockReturnValue(createStubPty());
    const { createPtyAdapter } = await import("./pty.js");

    const adapter = await createPtyAdapter({
      shell: "bash",
      args: ["-lc", "sleep 10"],
    });

    adapter.kill("SIGTERM");
    expect(ptyKillMock).toHaveBeenCalledWith("SIGTERM");
  });

  it("uses SIGKILL by default", async () => {
    spawnMock.mockReturnValue(createStubPty());
    const { createPtyAdapter } = await import("./pty.js");

    const adapter = await createPtyAdapter({
      shell: "bash",
      args: ["-lc", "sleep 10"],
    });

    adapter.kill();
    expect(ptyKillMock).toHaveBeenCalledWith("SIGKILL");
  });

  it("does not pass a signal to node-pty on Windows", async () => {
    const originalPlatform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { value: "win32", configurable: true });
    try {
      spawnMock.mockReturnValue(createStubPty());
      const { createPtyAdapter } = await import("./pty.js");

      const adapter = await createPtyAdapter({
        shell: "powershell.exe",
        args: ["-NoLogo"],
      });

      adapter.kill("SIGTERM");
      expect(ptyKillMock).toHaveBeenCalledWith(undefined);
    } finally {
      if (originalPlatform) {
        Object.defineProperty(process, "platform", originalPlatform);
      }
    }
  });
});
