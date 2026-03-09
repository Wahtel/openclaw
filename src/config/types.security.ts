export type SensitivePathGuardConfig = {
  /** Additional absolute paths to block from agent tool access. */
  extraPaths?: string[];
  /** Additional regex patterns (source strings) to block. */
  extraPatterns?: string[];
  /** Disable all built-in sensitive path patterns (use only extra*). */
  disableDefaults?: boolean;
};

export type SecurityConfig = {
  /** Sensitive path guard configuration for blocking agent tool access to credential files. */
  sensitivePathGuard?: SensitivePathGuardConfig;
  /** Additional env var names whose values should be scrubbed from tool output. */
  scrubSecretNames?: string[];
};
