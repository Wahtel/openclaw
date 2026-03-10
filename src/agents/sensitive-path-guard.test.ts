import os from "node:os";
import { describe, expect, it } from "vitest";
import {
  createSensitivePathGuard,
  execCommandReferencesSensitivePath,
  extractPathFromToolCall,
} from "./sensitive-path-guard.js";

const HOME = os.homedir();

describe("createSensitivePathGuard", () => {
  const guard = createSensitivePathGuard();

  describe("isSensitivePath", () => {
    it("blocks OpenClaw credential storage", () => {
      expect(guard.isSensitivePath(`${HOME}/.openclaw/credentials`)).toBe(true);
      expect(guard.isSensitivePath(`${HOME}/.openclaw/credentials/web.json`)).toBe(true);
    });

    it("blocks auth-profiles.json anywhere", () => {
      expect(guard.isSensitivePath("/some/path/auth-profiles.json")).toBe(true);
    });

    it("blocks SSH private keys", () => {
      expect(guard.isSensitivePath(`${HOME}/.ssh/id_rsa`)).toBe(true);
      expect(guard.isSensitivePath(`${HOME}/.ssh/id_ed25519`)).toBe(true);
      expect(guard.isSensitivePath(`${HOME}/.ssh/id_ecdsa`)).toBe(true);
    });

    it("blocks SSH config", () => {
      expect(guard.isSensitivePath(`${HOME}/.ssh/config`)).toBe(true);
    });

    it("blocks cloud provider credentials", () => {
      expect(guard.isSensitivePath(`${HOME}/.aws/credentials`)).toBe(true);
      expect(guard.isSensitivePath(`${HOME}/.aws/config`)).toBe(true);
      expect(guard.isSensitivePath(`${HOME}/.kube/config`)).toBe(true);
      expect(guard.isSensitivePath(`${HOME}/.docker/config.json`)).toBe(true);
      expect(guard.isSensitivePath(`${HOME}/.gcloud/foo`)).toBe(true);
      expect(guard.isSensitivePath(`${HOME}/.azure/foo`)).toBe(true);
    });

    it("blocks package manager credentials", () => {
      expect(guard.isSensitivePath(`${HOME}/.npmrc`)).toBe(true);
      expect(guard.isSensitivePath(`${HOME}/.pypirc`)).toBe(true);
      expect(guard.isSensitivePath(`${HOME}/.gem/credentials`)).toBe(true);
    });

    it("blocks GPG keyring", () => {
      expect(guard.isSensitivePath(`${HOME}/.gnupg/secring.gpg`)).toBe(true);
    });

    it("blocks netrc", () => {
      expect(guard.isSensitivePath(`${HOME}/.netrc`)).toBe(true);
    });

    it("blocks home .env files", () => {
      expect(guard.isSensitivePath(`${HOME}/.env`)).toBe(true);
      expect(guard.isSensitivePath(`${HOME}/.env.local`)).toBe(true);
      expect(guard.isSensitivePath(`${HOME}/.env.production`)).toBe(true);
    });

    it("allows workspace .env files", () => {
      expect(guard.isSensitivePath("/workspace/project/.env")).toBe(false);
      expect(guard.isSensitivePath("/tmp/project/.env.local")).toBe(false);
    });

    it("allows normal project files", () => {
      expect(guard.isSensitivePath("/workspace/project/src/index.ts")).toBe(false);
      expect(guard.isSensitivePath(`${HOME}/projects/app/README.md`)).toBe(false);
    });

    it("handles ~ expansion", () => {
      expect(guard.isSensitivePath("~/.ssh/id_rsa")).toBe(true);
      expect(guard.isSensitivePath("~/.aws/credentials")).toBe(true);
      expect(guard.isSensitivePath("~/.openclaw/credentials/web.json")).toBe(true);
    });

    it("catches .. traversal", () => {
      expect(guard.isSensitivePath(`${HOME}/projects/../.ssh/id_rsa`)).toBe(true);
      expect(guard.isSensitivePath(`${HOME}/foo/bar/../../.aws/credentials`)).toBe(true);
    });
  });

  describe("getSensitivePathReason", () => {
    it("returns a reason for sensitive paths", () => {
      const reason = guard.getSensitivePathReason(`${HOME}/.ssh/id_rsa`);
      expect(reason).toBe("SSH private key");
    });

    it("returns undefined for non-sensitive paths", () => {
      expect(guard.getSensitivePathReason("/tmp/safe.txt")).toBeUndefined();
    });
  });

  describe("isSensitivePathResolved", () => {
    it("checks lexical path", async () => {
      expect(await guard.isSensitivePathResolved(`${HOME}/.ssh/id_rsa`)).toBe(true);
      expect(await guard.isSensitivePathResolved("/tmp/safe.txt")).toBe(false);
    });
  });
});

describe("createSensitivePathGuard with config", () => {
  it("supports extraPaths", () => {
    const guard = createSensitivePathGuard({
      extraPaths: ["/custom/secrets"],
    });
    expect(guard.isSensitivePath("/custom/secrets")).toBe(true);
    expect(guard.isSensitivePath("/custom/secrets/key.pem")).toBe(true);
    expect(guard.isSensitivePath("/custom/other")).toBe(false);
  });

  it("supports extraPatterns", () => {
    const guard = createSensitivePathGuard({
      extraPatterns: ["\\.secret$"],
    });
    expect(guard.isSensitivePath("/tmp/data.secret")).toBe(true);
    expect(guard.isSensitivePath("/tmp/data.txt")).toBe(false);
  });

  it("disableDefaults removes built-in patterns", () => {
    const guard = createSensitivePathGuard({
      disableDefaults: true,
      extraPaths: ["/only/this"],
    });
    expect(guard.isSensitivePath(`${HOME}/.ssh/id_rsa`)).toBe(false);
    expect(guard.isSensitivePath("/only/this/key")).toBe(true);
  });

  it("ignores invalid extra patterns", () => {
    const guard = createSensitivePathGuard({
      extraPatterns: ["[invalid"],
    });
    // Should not throw; invalid pattern is silently skipped.
    expect(guard.isSensitivePath("/tmp/safe.txt")).toBe(false);
  });
});

describe("extractPathFromToolCall", () => {
  it("extracts path from read tool", () => {
    expect(extractPathFromToolCall("read", { path: "/etc/passwd" })).toBe("/etc/passwd");
    expect(extractPathFromToolCall("read", { file: "/etc/passwd" })).toBe("/etc/passwd");
    expect(extractPathFromToolCall("read", { filePath: "/etc/passwd" })).toBe("/etc/passwd");
  });

  it("extracts file_path (Claude Code-style alias) from file tools", () => {
    expect(extractPathFromToolCall("read", { file_path: "/etc/passwd" })).toBe("/etc/passwd");
    expect(extractPathFromToolCall("write", { file_path: "/etc/shadow" })).toBe("/etc/shadow");
    expect(extractPathFromToolCall("edit", { file_path: "~/.ssh/id_rsa" })).toBe("~/.ssh/id_rsa");
    expect(extractPathFromToolCall("apply_patch", { file_path: "/tmp/x" })).toBe("/tmp/x");
  });

  it("extracts path from write/edit tools", () => {
    expect(extractPathFromToolCall("write", { path: "/tmp/out.txt" })).toBe("/tmp/out.txt");
    expect(extractPathFromToolCall("edit", { path: "/tmp/out.txt" })).toBe("/tmp/out.txt");
    expect(extractPathFromToolCall("apply_patch", { path: "/tmp/out.txt" })).toBe("/tmp/out.txt");
  });

  it("extracts command from exec tools", () => {
    expect(extractPathFromToolCall("exec", { command: "cat /etc/passwd" })).toBe("cat /etc/passwd");
    expect(extractPathFromToolCall("bash", { command: "ls -la" })).toBe("ls -la");
    expect(extractPathFromToolCall("shell", { cmd: "echo hi" })).toBe("echo hi");
  });

  it("returns undefined for unknown tools", () => {
    expect(extractPathFromToolCall("web_fetch", { url: "http://example.com" })).toBeUndefined();
  });

  it("returns undefined for missing params", () => {
    expect(extractPathFromToolCall("read", null)).toBeUndefined();
    expect(extractPathFromToolCall("read", {})).toBeUndefined();
    expect(extractPathFromToolCall("read", { path: 123 })).toBeUndefined();
  });

  it("normalizes tool names case-insensitively", () => {
    expect(extractPathFromToolCall("Read", { path: "/tmp/x" })).toBe("/tmp/x");
    expect(extractPathFromToolCall("EXEC", { command: "ls" })).toBe("ls");
  });
});

describe("execCommandReferencesSensitivePath", () => {
  const guard = createSensitivePathGuard();

  it("detects sensitive paths in commands using absolute paths", () => {
    const reason = execCommandReferencesSensitivePath(`cat ${HOME}/.ssh/id_rsa`, guard);
    expect(reason).toBeDefined();
  });

  it("detects sensitive paths in commands using ~ paths", () => {
    const reason = execCommandReferencesSensitivePath("cat ~/.aws/credentials", guard);
    expect(reason).toBeDefined();
  });

  it("detects openclaw credential paths", () => {
    const reason = execCommandReferencesSensitivePath(`cat ${HOME}/.openclaw/credentials`, guard);
    expect(reason).toBeDefined();
  });

  it("returns undefined for safe commands", () => {
    expect(execCommandReferencesSensitivePath("ls -la /tmp", guard)).toBeUndefined();
    expect(execCommandReferencesSensitivePath("echo hello", guard)).toBeUndefined();
  });

  it("detects auth-profiles.json", () => {
    const reason = execCommandReferencesSensitivePath("cat /auth-profiles.json", guard);
    expect(reason).toBeDefined();
  });
});
