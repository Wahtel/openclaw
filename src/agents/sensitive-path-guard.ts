import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createSubsystemLogger } from "../logging/subsystem.js";

const log = createSubsystemLogger("agents/sensitive-path-guard");

export type SensitivePathGuardConfig = {
  /** Additional absolute paths to block. */
  extraPaths?: string[];
  /** Additional patterns (regex source strings) to block. */
  extraPatterns?: string[];
  /** Disable all built-in patterns (use only extraPaths/extraPatterns). */
  disableDefaults?: boolean;
};

type PatternEntry = {
  pattern: RegExp;
  reason: string;
};

const HOME = os.homedir();

/**
 * Built-in sensitive path patterns.
 * Each pattern matches against the resolved absolute path.
 */
function getDefaultPatterns(): PatternEntry[] {
  // Escape special regex characters in home directory path.
  const h = escapeRegExp(HOME);
  return [
    // OpenClaw credential storage
    {
      pattern: new RegExp(`${h}/\\.openclaw/credentials(/|$)`, "i"),
      reason: "OpenClaw credential storage",
    },
    { pattern: /\/auth-profiles\.json$/i, reason: "auth profile" },

    // SSH keys and config
    { pattern: new RegExp(`${h}/\\.ssh/id_`), reason: "SSH private key" },
    { pattern: new RegExp(`${h}/\\.ssh/config$`), reason: "SSH config" },
    { pattern: new RegExp(`${h}/\\.ssh/known_hosts$`), reason: "SSH known hosts" },

    // Cloud provider credentials
    { pattern: new RegExp(`${h}/\\.aws/credentials$`), reason: "AWS credentials" },
    { pattern: new RegExp(`${h}/\\.aws/config$`), reason: "AWS config" },
    { pattern: new RegExp(`${h}/\\.kube/config$`), reason: "Kubernetes config" },
    { pattern: new RegExp(`${h}/\\.docker/config\\.json$`), reason: "Docker config" },
    { pattern: new RegExp(`${h}/\\.gcloud/`), reason: "Google Cloud credentials" },
    { pattern: new RegExp(`${h}/\\.azure/`), reason: "Azure credentials" },

    // Package manager credentials
    { pattern: new RegExp(`${h}/\\.npmrc$`), reason: "npm credentials" },
    { pattern: new RegExp(`${h}/\\.pypirc$`), reason: "PyPI credentials" },
    { pattern: new RegExp(`${h}/\\.gem/credentials$`), reason: "RubyGems credentials" },

    // General secrets
    { pattern: new RegExp(`${h}/\\.gnupg/`), reason: "GPG keyring" },
    { pattern: new RegExp(`${h}/\\.netrc$`), reason: "netrc credentials" },

    // Dotenv files in home directory (not in workspace)
    { pattern: new RegExp(`${h}/\\.env$`), reason: "home .env file" },
    { pattern: new RegExp(`${h}/\\.env\\.[a-zA-Z]+$`), reason: "home .env file" },
  ];
}

function escapeRegExp(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export type SensitivePathGuard = {
  /** Check if a file path targets a sensitive location. */
  isSensitivePath(filePath: string): boolean;
  /** Return the reason a path is sensitive, or undefined if not. */
  getSensitivePathReason(filePath: string): string | undefined;
  /** Resolve symlinks and check the real path. Async variant for thorough checking. */
  isSensitivePathResolved(filePath: string): Promise<boolean>;
};

export function createSensitivePathGuard(config?: SensitivePathGuardConfig): SensitivePathGuard {
  const patterns: PatternEntry[] = [];

  if (!config?.disableDefaults) {
    patterns.push(...getDefaultPatterns());
  }

  // Add user-configured extra paths as exact-prefix patterns.
  if (config?.extraPaths) {
    for (const p of config.extraPaths) {
      const resolved = path.resolve(p);
      const escaped = escapeRegExp(resolved);
      patterns.push({
        pattern: new RegExp(`^${escaped}(/|$)`),
        reason: "user-configured sensitive path",
      });
    }
  }

  // Add user-configured extra patterns.
  if (config?.extraPatterns) {
    for (const src of config.extraPatterns) {
      try {
        patterns.push({
          pattern: new RegExp(src, "i"),
          reason: "user-configured sensitive pattern",
        });
      } catch {
        log.warn(`Invalid sensitive path pattern: ${src}`);
      }
    }
  }

  function checkPath(resolvedPath: string): string | undefined {
    const normalized = path.resolve(resolvedPath);
    for (const entry of patterns) {
      if (entry.pattern.test(normalized)) {
        return entry.reason;
      }
    }
    return undefined;
  }

  return {
    isSensitivePath(filePath: string): boolean {
      // Expand ~ to home directory.
      const expanded = filePath.startsWith("~") ? path.join(HOME, filePath.slice(1)) : filePath;
      const resolved = path.resolve(expanded);
      return checkPath(resolved) !== undefined;
    },

    getSensitivePathReason(filePath: string): string | undefined {
      const expanded = filePath.startsWith("~") ? path.join(HOME, filePath.slice(1)) : filePath;
      const resolved = path.resolve(expanded);
      return checkPath(resolved);
    },

    async isSensitivePathResolved(filePath: string): Promise<boolean> {
      const expanded = filePath.startsWith("~") ? path.join(HOME, filePath.slice(1)) : filePath;
      const lexical = path.resolve(expanded);

      // Check the lexical path first (fast path).
      if (checkPath(lexical) !== undefined) {
        return true;
      }

      // Resolve symlinks and check the real path too.
      try {
        const real = await fs.realpath(lexical);
        if (real !== lexical && checkPath(real) !== undefined) {
          return true;
        }
      } catch {
        // File doesn't exist or can't resolve — lexical check is sufficient.
      }

      return false;
    },
  };
}

/**
 * Extract a file path from tool call parameters, if the tool operates on files.
 * Returns undefined for tools that don't have a path parameter.
 */
export function extractPathFromToolCall(toolName: string, params: unknown): string | undefined {
  if (!params || typeof params !== "object") {
    return undefined;
  }
  const record = params as Record<string, unknown>;
  const normalized = toolName.toLowerCase().replace(/[^a-z0-9]/g, "_");

  // read, write, edit tools — direct path parameter
  if (
    normalized === "read" ||
    normalized === "write" ||
    normalized === "edit" ||
    normalized === "apply_patch"
  ) {
    const p = record.path ?? record.file ?? record.filePath;
    return typeof p === "string" ? p : undefined;
  }

  // exec tool — scan the command string for sensitive path substrings
  if (normalized === "exec" || normalized === "shell" || normalized === "bash") {
    const cmd = record.command ?? record.cmd ?? record.script;
    return typeof cmd === "string" ? cmd : undefined;
  }

  return undefined;
}

/**
 * For exec-style tools, check if the command string references any sensitive paths.
 * Unlike file tools where we check the exact path, here we substring-match
 * against expanded sensitive path strings.
 */
export function execCommandReferencesSensitivePath(
  command: string,
  guard: SensitivePathGuard,
): string | undefined {
  // Common sensitive file paths to check against the command string.
  const sensitivePathCandidates = [
    `${HOME}/.openclaw/credentials`,
    `${HOME}/.openclaw/auth-profiles.json`,
    `~/.openclaw/credentials`,
    `~/.openclaw/auth-profiles.json`,
    `${HOME}/.ssh/id_rsa`,
    `${HOME}/.ssh/id_ed25519`,
    `${HOME}/.ssh/id_ecdsa`,
    `${HOME}/.ssh/config`,
    `~/.ssh/id_rsa`,
    `~/.ssh/id_ed25519`,
    `~/.ssh/config`,
    `${HOME}/.aws/credentials`,
    `~/.aws/credentials`,
    `${HOME}/.docker/config.json`,
    `~/.docker/config.json`,
    `${HOME}/.kube/config`,
    `~/.kube/config`,
    `${HOME}/.npmrc`,
    `~/.npmrc`,
    `${HOME}/.pypirc`,
    `~/.pypirc`,
    `${HOME}/.netrc`,
    `~/.netrc`,
    `${HOME}/.gnupg/`,
    `~/.gnupg/`,
    `${HOME}/.env`,
    "/auth-profiles.json",
  ];

  for (const candidate of sensitivePathCandidates) {
    if (command.includes(candidate)) {
      const reason = guard.getSensitivePathReason(candidate);
      if (reason) {
        return reason;
      }
    }
  }

  return undefined;
}
