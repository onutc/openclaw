import { describe, expect, it } from "vitest";
import { createRunRegistry } from "./registry.js";

describe("process supervisor run registry", () => {
  it("finalize is idempotent and preserves first terminal metadata", () => {
    const registry = createRunRegistry();
    registry.add({
      runId: "r1",
      sessionId: "s1",
      backendId: "b1",
      state: "running",
      startedAtMs: 1,
      lastOutputAtMs: 1,
      createdAtMs: 1,
      updatedAtMs: 1,
    });

    const first = registry.finalize("r1", {
      reason: "overall-timeout",
      exitCode: null,
      exitSignal: "SIGKILL",
    });
    const second = registry.finalize("r1", {
      reason: "manual-cancel",
      exitCode: 0,
      exitSignal: null,
    });

    expect(first).not.toBeNull();
    expect(first?.firstFinalize).toBe(true);
    expect(first?.record.terminationReason).toBe("overall-timeout");
    expect(first?.record.exitCode).toBeNull();
    expect(first?.record.exitSignal).toBe("SIGKILL");

    expect(second).not.toBeNull();
    expect(second?.firstFinalize).toBe(false);
    expect(second?.record.terminationReason).toBe("overall-timeout");
    expect(second?.record.exitCode).toBeNull();
    expect(second?.record.exitSignal).toBe("SIGKILL");
  });
});
