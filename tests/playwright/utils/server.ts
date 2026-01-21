// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { spawn } from "child_process";
import http from "http";
import os from "os";
import path from "path";

export type ServerHandle = {
  baseUrl: string;
  port: number;
  stop: () => Promise<void>;
};

const activeChildren = new Set<ReturnType<typeof spawn>>();
let cleanupInstalled = false;
let cleanupPromise: Promise<void> | null = null;

export async function launchServer(options: {
  runtimeRoot: string;
  port: number;
  timeoutMs?: number;
}): Promise<ServerHandle> {
  const repoRoot = path.resolve(__dirname, "..", "..", "..");
  const nopDir = path.join(repoRoot, "nop");
  const cargoWrapper = path.join(repoRoot, "scripts", "cargo.sh");
  const baseUrl = `http://127.0.0.1:${options.port}`;
  const timeoutMs = options.timeoutMs ?? 120_000;

  const binary = process.env.NOP_BINARY;
  const args = binary
    ? ["-C", options.runtimeRoot, "-F"]
    : ["run", "--", "-C", options.runtimeRoot, "-F"];
  const command = binary ?? cargoWrapper;
  const passthroughLogs = process.env.NOP_PW_SERVER_LOG === "1";

  let buffered = "";
  const child = spawn(command, args, {
    cwd: nopDir,
    env: {
      ...process.env,
      CARGO_TARGET_DIR:
        process.env.CARGO_TARGET_DIR ??
        path.join(os.tmpdir(), "nopressure-pw-cargo"),
      RUST_LOG: process.env.RUST_LOG ?? "warn",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  trackChild(child);

  child.stdout?.on("data", (chunk) => {
    buffered = appendBuffer(buffered, chunk);
    if (passthroughLogs) {
      process.stdout.write(chunk);
    }
  });
  child.stderr?.on("data", (chunk) => {
    buffered = appendBuffer(buffered, chunk);
    if (passthroughLogs) {
      process.stderr.write(chunk);
    }
  });

  try {
    await waitForServer(baseUrl, timeoutMs);
  } catch (error) {
    await stopProcess(child);
    const output = buffered.trim();
    const detail = output ? `\n\nProcess output:\n${output}` : "";
    throw new Error(`Server failed to start: ${String(error)}${detail}`);
  }

  return {
    baseUrl,
    port: options.port,
    stop: async () => {
      await stopProcess(child);
      activeChildren.delete(child);
    },
  };
}

export async function launchBootstrapServer(options: {
  runtimeRoot: string;
  port: number;
  timeoutMs?: number;
  passwordTimeoutMs?: number;
}): Promise<ServerHandle & { bootstrapPassword: string }> {
  const repoRoot = path.resolve(__dirname, "..", "..", "..");
  const nopDir = path.join(repoRoot, "nop");
  const cargoWrapper = path.join(repoRoot, "scripts", "cargo.sh");
  const baseUrl = `http://127.0.0.1:${options.port}`;
  const timeoutMs = options.timeoutMs ?? 120_000;
  const passwordTimeoutMs = options.passwordTimeoutMs ?? timeoutMs;

  const binary = process.env.NOP_BINARY;
  const args = binary
    ? ["-C", options.runtimeRoot, "-F"]
    : ["run", "--", "-C", options.runtimeRoot, "-F"];
  const command = binary ?? cargoWrapper;
  const passthroughLogs = process.env.NOP_PW_SERVER_LOG === "1";

  let buffered = "";
  let bootstrapPassword: string | null = null;
  let resolvePassword: ((value: string) => void) | null = null;
  let rejectPassword: ((reason: Error) => void) | null = null;
  const passwordPattern =
    /\[bootstrap\] WARNING: admin@example\.com password: ([A-Za-z0-9]+)/;
  const passwordPromise = new Promise<string>((resolve, reject) => {
    resolvePassword = resolve;
    rejectPassword = reject;
  });

  const child = spawn(command, args, {
    cwd: nopDir,
    env: {
      ...process.env,
      CARGO_TARGET_DIR:
        process.env.CARGO_TARGET_DIR ??
        path.join(os.tmpdir(), "nopressure-pw-cargo"),
      RUST_LOG: process.env.RUST_LOG ?? "warn",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  trackChild(child);

  const capturePassword = (chunk: Buffer) => {
    buffered = appendBuffer(buffered, chunk);
    if (bootstrapPassword) {
      return;
    }
    const match = passwordPattern.exec(buffered);
    if (match) {
      bootstrapPassword = match[1];
      resolvePassword?.(bootstrapPassword);
    }
  };

  child.stdout?.on("data", (chunk) => {
    capturePassword(chunk);
    if (passthroughLogs) {
      process.stdout.write(chunk);
    }
  });
  child.stderr?.on("data", (chunk) => {
    capturePassword(chunk);
    if (passthroughLogs) {
      process.stderr.write(chunk);
    }
  });

  const passwordTimeout = setTimeout(() => {
    rejectPassword?.(new Error("Timed out waiting for bootstrap password"));
  }, passwordTimeoutMs);

  try {
    const [password] = await Promise.all([
      passwordPromise,
      waitForServer(baseUrl, timeoutMs),
    ]);
    clearTimeout(passwordTimeout);
    return {
      baseUrl,
      port: options.port,
      bootstrapPassword: password,
      stop: async () => {
        await stopProcess(child);
        activeChildren.delete(child);
      },
    };
  } catch (error) {
    clearTimeout(passwordTimeout);
    await stopProcess(child);
    const output = buffered.trim();
    const detail = output ? `\n\nProcess output:\n${output}` : "";
    throw new Error(`Server failed to start: ${String(error)}${detail}`);
  }
}

function appendBuffer(buffered: string, chunk: Buffer): string {
  const next = buffered + chunk.toString();
  if (next.length <= 8000) {
    return next;
  }
  return next.slice(next.length - 8000);
}

async function waitForServer(baseUrl: string, timeoutMs: number): Promise<void> {
  const start = Date.now();

  while (Date.now() - start < timeoutMs) {
    const ready = await checkServer(baseUrl);
    if (ready) {
      return;
    }
    await delay(200);
  }

  throw new Error(`Timed out waiting for ${baseUrl}`);
}

function checkServer(baseUrl: string): Promise<boolean> {
  return new Promise((resolve) => {
    const req = http.get(baseUrl, (res) => {
      res.resume();
      resolve(res.statusCode === 200);
    });

    req.on("error", () => resolve(false));
    req.setTimeout(1000, () => {
      req.destroy();
      resolve(false);
    });
  });
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function stopProcess(child: ReturnType<typeof spawn>): Promise<void> {
  if (child.exitCode !== null || child.killed) {
    return;
  }

  const exitPromise = new Promise<void>((resolve) => {
    child.once("exit", () => resolve());
  });

  child.kill("SIGTERM");

  const timeout = new Promise<void>((resolve) => {
    setTimeout(resolve, 5_000);
  });

  await Promise.race([exitPromise, timeout]);

  if (child.exitCode === null && !child.killed) {
    child.kill("SIGKILL");
    await exitPromise;
  }
}

function trackChild(child: ReturnType<typeof spawn>): void {
  activeChildren.add(child);
  child.once("exit", () => {
    activeChildren.delete(child);
  });

  if (!cleanupInstalled) {
    installCleanupHandlers();
  }
}

function installCleanupHandlers(): void {
  cleanupInstalled = true;

  const cleanupAll = async (): Promise<void> => {
    if (cleanupPromise) {
      return cleanupPromise;
    }
    cleanupPromise = Promise.allSettled(
      Array.from(activeChildren).map((child) => stopProcess(child))
    ).then(() => {
      activeChildren.clear();
    });
    return cleanupPromise;
  };

  const handleSignal = (signal: NodeJS.Signals) => {
    void cleanupAll().finally(() => {
      process.exit(signal === "SIGINT" ? 130 : 0);
    });
  };

  process.once("SIGINT", () => handleSignal("SIGINT"));
  process.once("SIGTERM", () => handleSignal("SIGTERM"));
  process.once("SIGHUP", () => handleSignal("SIGHUP"));
  process.once("beforeExit", () => {
    void cleanupAll();
  });
  process.once("exit", () => {
    for (const child of activeChildren) {
      child.kill("SIGTERM");
    }
  });
}
