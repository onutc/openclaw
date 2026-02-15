---
summary: "Production plan for reliable interactive process supervision (PTY + non-PTY) with explicit ownership, unified lifecycle, and deterministic cleanup"
owner: "openclaw"
status: "in-progress"
last_updated: "2026-02-15"
title: "PTY and Process Supervision Plan"
---

# PTY and Process Supervision Plan

## 1. What we are solving

We want reliable interactive command execution for agent workflows.

In plain language:

- `exec` should be able to start both normal and terminal-like commands.
- long-running commands should be safe to background.
- `process` should let us continue interacting with those runs (poll output, send keys, paste, submit, kill).
- timeouts and cancellation should be predictable.
- cleanup must never kill unrelated processes.

The core objective is not "add PTY". The objective is one trustworthy lifecycle for process runs.

## 2. System goal and boundaries

### Goal

Provide a single, production-safe process lifecycle model for:

- PTY runs (`pty: true`) for terminal-required CLIs.
- non-PTY runs for normal command execution.
- background continuation via the `process` tool.

### Non-goals (for this plan)

- full terminal multiplexer behavior (tmux-like features).
- durable terminal replay across restart.
- introducing a new workspace package for supervisor code.

### Scope location

- Keep implementation internal under `src/process/supervisor`.
- Do not move this to `extensions/*`.

## 3. Current state (as of this branch)

The branch already moved major lifecycle logic into supervisor:

- Added supervisor module:
  - `src/process/supervisor/types.ts`
  - `src/process/supervisor/registry.ts`
  - `src/process/supervisor/supervisor.ts`
  - `src/process/supervisor/adapters/child.ts`
  - `src/process/supervisor/adapters/pty.ts`
  - `src/process/supervisor/index.ts`
- Wired CLI runner to supervisor watchdog/scope model.
- Wired `runExecProcess` to supervisor spawn/wait/cancel.
- Removed legacy resume cleanup config path.
- Added/updated tests around supervisor and PTY cleanup behavior.

This is a strong base, but not the final production shape yet.

## 4. Fundamental changes we still need

These are the key architecture decisions that matter most for production quality.

### A. One lifecycle owner (mandatory)

Problem:

- lifecycle control is split: supervisor manages runs, but `process` still kills via PID tree helpers.

Required change:

- supervisor becomes the single authority for run lifecycle.
- `process` actions should call supervisor APIs for cancel/status paths.
- avoid duplicate finalization and split ownership.

Why:

- removes race conditions.
- prevents state mismatch between registry/session and actual process state.

### B. Explicit PTY command contract (mandatory)

Problem:

- PTY spawn currently reconstructs command text from `argv` inside supervisor (`join(" ")` semantics in practice).
- reconstruction is lossy and can break quoting/escaping edge cases.

Required change:

- pass PTY command data explicitly.
- do not rebuild PTY command from generic argv inside supervisor.

Why:

- correctness and safety for complex shell arguments.
- predictable behavior across shells/platforms.

### C. Remove process -> agents type coupling (mandatory)

Problem:

- process supervisor adapters import `SessionStdin` from the agents layer.

Required change:

- move stdin contract type to process-level shared types.
- ensure `src/process/**` does not depend on `src/agents/**` types.

Why:

- clean layering.
- easier future reuse and safer refactors.

### D. Decide durability policy explicitly (product decision)

Problem:

- supervisor registry is in-memory only.
- `reconcileOrphans()` is currently a stub.

Required decision:

- choose one:
  1. keep in-memory only and document restart boundary.
  2. implement persistent run metadata + reconciliation.

Why:

- this is a foundational behavior boundary, not a minor detail.

### E. Reduce runtime complexity in `runExecProcess` (strongly recommended)

Problem:

- one large function currently handles setup, spawn spec, fallback, stream handling, and outcome mapping.

Required change:

- split into focused helpers while preserving behavior.

Why:

- improves readability, debugging, and testability.

### F. Single source of truth for watchdog defaults (recommended)

Problem:

- watchdog defaults are duplicated across backend defaults and runtime resolver logic.

Required change:

- centralize defaults and consume from one place.

Why:

- avoids config drift and hidden behavior mismatch.

## 5. Cohesive implementation plan

Implement in two phases to reduce risk.

## Phase 1: Architecture hardening (behavior-compatible)

1. Lock supervisor as lifecycle owner.

- Add missing supervisor APIs needed by `process` tool operations.
- Route `process kill/remove` through supervisor cancellation path.
- Ensure finalization remains idempotent and single-path.

2. Introduce explicit PTY spawn input model.

- Extend supervisor spawn input with PTY-specific command contract.
- Remove PTY command reconstruction from generic argv.
- Update exec runtime to pass explicit PTY command data.

3. Decouple process typings from agents.

- Move stdin/session I/O contract type used by supervisor adapters into process-level types.
- Remove imports from `src/agents/bash-process-registry.ts` in `src/process/supervisor/*`.

4. Refactor `runExecProcess` into helpers.

- Extract:
  - spawn spec builder
  - supervisor spawn/fallback helper
  - stdout/stderr handling helper
  - exit mapping helper
- keep external behavior unchanged in this phase.

5. Unify watchdog default constants.

- Centralize watchdog baseline defaults.
- Use same constants in backend defaults and timeout resolver logic.

Deliverable for Phase 1:

- same user-facing behavior, cleaner contracts, fewer race/coupling risks.

## Phase 2: Durability and reconciliation (if enabled)

1. Implement persistent run metadata store for active runs.

- store `runId`, `pid`, ownership metadata, timestamps, state.

2. Implement real `reconcileOrphans()`.

- on startup:
  - load active records
  - verify liveness
  - resolve stale records
  - cancel/clean owned orphans deterministically

3. Define and test lease/ownership behavior if multi-instance ownership can happen.

Deliverable for Phase 2:

- consistent restart behavior and deterministic orphan handling.

If durability is explicitly out of scope:

- keep registry in-memory.
- document that active interactive sessions are not guaranteed across restart.

## 6. File-by-file work map

### Supervisor core

- `src/process/supervisor/types.ts`
  - add explicit PTY command contract types.
  - host shared stdin contract types.
- `src/process/supervisor/supervisor.ts`
  - remove PTY command reconstruction.
  - keep one finalize path.
  - implement real reconciliation if Phase 2 enabled.
- `src/process/supervisor/registry.ts`
  - keep idempotent finalize semantics.
  - extend for durability metadata if Phase 2.
- `src/process/supervisor/adapters/pty.ts`
  - preserve kill-settles-wait guarantee.
  - ensure listener disposal remains exactly-once.
- `src/process/supervisor/adapters/child.ts`
  - keep stdin mode correctness and typed contracts.

### Exec/process integration

- `src/agents/bash-tools.exec-runtime.ts`
  - split monolithic runtime function.
  - pass explicit PTY contract.
- `src/agents/bash-tools.exec.ts`
  - keep orchestration thin.
  - ensure approvals/safety semantics remain unchanged.
- `src/agents/bash-tools.process.ts`
  - call supervisor-driven lifecycle APIs instead of direct PID-tree kill paths where applicable.

### CLI runner integration

- `src/agents/cli-runner.ts`
  - retain supervisor lifecycle usage and scope ownership semantics.
- `src/agents/cli-runner/reliability.ts`
  - consume centralized watchdog defaults.
- `src/agents/cli-backends.ts`
  - consume same watchdog defaults source.

## 7. Testing plan

### Must-pass targeted tests

- `src/process/supervisor/registry.test.ts`
- `src/process/supervisor/supervisor.test.ts`
- `src/agents/bash-tools.exec.pty-cleanup.test.ts`
- `src/agents/bash-tools.exec.pty-fallback.e2e.test.ts`
- `src/agents/bash-tools.exec.background-abort.e2e.test.ts`
- `src/agents/bash-tools.process.send-keys.e2e.test.ts`
- `src/agents/cli-runner.e2e.test.ts`
- `src/process/exec.test.ts`

### Additional tests to add during plan completion

1. PTY command contract tests.

- quoted args and special chars survive exact execution.
- no join/reconstruction artifacts.

2. Single-owner lifecycle tests.

- `process kill` path converges through supervisor.
- no duplicate finalize on cancel+exit races.

3. Reconciliation tests (if Phase 2 enabled).

- stale active records are resolved deterministically.
- live owned runs are reconciled correctly.

## 8. Operational safety requirements

Do not regress these guarantees while refactoring:

- host env variable hardening checks.
- approval and allowlist policy gates.
- output sanitization.
- output memory caps.
- no broad process-table text matching kill logic.

## 9. Definition of done

This work is complete when all are true:

1. Supervisor is the only lifecycle owner for managed runs.
2. PTY command handling uses explicit contract, no lossy reconstruction.
3. Process layer has no type dependency on agents layer.
4. Watchdog defaults are single-source and consistent.
5. Targeted tests above are green.
6. Lint/format checks are green.
7. Durability boundary is explicit:
   - either real reconciliation implemented and tested,
   - or in-memory-only behavior documented as an intentional boundary.

## 10. Rollout strategy

1. Land Phase 1 first (safe refactor + contract hardening).
2. Keep behavior parity and verify with targeted tests.
3. If durability is required, land Phase 2 in focused follow-up.
4. Do not mix unrelated failing suites into acceptance for this plan unless explicitly requested.

## 11. Summary

The right long-term shape is:

- one owner,
- one lifecycle,
- explicit PTY command contract,
- deterministic cleanup,
- clear restart story.

The current branch already moved strongly in this direction. This plan finishes it in a production-ready, maintainable way.
