/**
 * Secret value scrubbing for tool output.
 *
 * Collects known secret values from environment variables and provides
 * a function to replace them with [REDACTED:name] in arbitrary text.
 */

const BLOCKED_ENV_VAR_PATTERNS: ReadonlyArray<RegExp> = [
  /^ANTHROPIC_API_KEY$/i,
  /^OPENAI_API_KEY$/i,
  /^GEMINI_API_KEY$/i,
  /^OPENROUTER_API_KEY$/i,
  /^MINIMAX_API_KEY$/i,
  /^ELEVENLABS_API_KEY$/i,
  /^SYNTHETIC_API_KEY$/i,
  /^TELEGRAM_BOT_TOKEN$/i,
  /^DISCORD_BOT_TOKEN$/i,
  /^SLACK_(BOT|APP)_TOKEN$/i,
  /^LINE_CHANNEL_SECRET$/i,
  /^LINE_CHANNEL_ACCESS_TOKEN$/i,
  /^OPENCLAW_GATEWAY_(TOKEN|PASSWORD)$/i,
  /^AWS_(SECRET_ACCESS_KEY|SECRET_KEY|SESSION_TOKEN)$/i,
  /^(GH|GITHUB)_TOKEN$/i,
  /^(AZURE|AZURE_OPENAI|COHERE|AI_GATEWAY|OPENROUTER)_API_KEY$/i,
  /_?(API_KEY|TOKEN|PASSWORD|PRIVATE_KEY|SECRET)$/i,
];

const DEFAULT_MIN_VALUE_LENGTH = 6;

export type SecretValueSet = {
  /** name -> plaintext value */
  entries: Map<string, string>;
  /** [name, value] sorted by value length desc, for longest-first replacement */
  sortedValues: [string, string][];
};

function matchesAnyPattern(key: string, patterns: readonly RegExp[]): boolean {
  return patterns.some((p) => p.test(key));
}

/**
 * Build a set of secret values from env vars matching blocked patterns.
 */
export function buildSecretValueSet(params: {
  env?: Record<string, string | undefined>;
  extraSecretNames?: string[];
  /** Explicit secret values to scrub (e.g. from auth-profiles). */
  extraSecretValues?: Array<{ name: string; value: string }>;
  minLength?: number;
}): SecretValueSet {
  const entries = new Map<string, string>();
  const minLength = params.minLength ?? DEFAULT_MIN_VALUE_LENGTH;
  const env = params.env ?? {};

  // Collect values from env vars matching blocked patterns.
  for (const [key, value] of Object.entries(env)) {
    if (!value || value.length < minLength) {
      continue;
    }
    if (matchesAnyPattern(key, BLOCKED_ENV_VAR_PATTERNS)) {
      entries.set(key, value);
    }
  }

  // Add user-configured extra secret names.
  if (params.extraSecretNames) {
    for (const name of params.extraSecretNames) {
      const value = env[name];
      if (value && value.length >= minLength) {
        entries.set(name, value);
      }
    }
  }

  // Add explicit secret values (e.g. from auth-profiles.json).
  if (params.extraSecretValues) {
    for (const { name, value } of params.extraSecretValues) {
      if (value && value.length >= minLength) {
        entries.set(name, value);
      }
    }
  }

  // Sort by value length descending for longest-first replacement.
  const sortedValues = [...entries.entries()].toSorted((a, b) => b[1].length - a[1].length);

  return { entries, sortedValues };
}

export type ScrubResult = {
  text: string;
  redacted: boolean;
  redactedNames: string[];
};

/**
 * Replace any known secret values in text with [REDACTED:name].
 *
 * Uses longest-first replacement to avoid partial-match issues.
 * Also checks base64-encoded variants of each value.
 */
export function scrubSecrets(text: string, secrets: SecretValueSet): ScrubResult {
  if (secrets.sortedValues.length === 0) {
    return { text, redacted: false, redactedNames: [] };
  }

  let result = text;
  const redactedNames: string[] = [];

  for (const [name, value] of secrets.sortedValues) {
    const sentinel = `[REDACTED:${name}]`;

    // Check plain value.
    if (result.includes(value)) {
      result = result.replaceAll(value, sentinel);
      redactedNames.push(name);
      continue;
    }

    // Check base64-encoded variant.
    const b64 = Buffer.from(value).toString("base64");
    if (b64.length >= DEFAULT_MIN_VALUE_LENGTH && result.includes(b64)) {
      result = result.replaceAll(b64, sentinel);
      redactedNames.push(name);
    }
  }

  return {
    text: result,
    redacted: redactedNames.length > 0,
    redactedNames,
  };
}

/**
 * Walk a tool result structure and scrub secrets from all text content.
 *
 * Handles the standard tool result shape: { content: [{ type: "text", text: "..." }] }
 */
export function scrubToolResultContent(result: unknown, secrets: SecretValueSet): unknown {
  if (!result || typeof result !== "object") {
    return result;
  }
  if (secrets.sortedValues.length === 0) {
    return result;
  }

  const record = result as Record<string, unknown>;
  const content = Array.isArray(record.content) ? record.content : null;
  if (!content) {
    return result;
  }

  let anyRedacted = false;
  const scrubbed = content.map((item) => {
    if (!item || typeof item !== "object") {
      return item;
    }
    const entry = item as Record<string, unknown>;
    if (entry.type === "text" && typeof entry.text === "string") {
      const scrubResult = scrubSecrets(entry.text, secrets);
      if (scrubResult.redacted) {
        anyRedacted = true;
        return { ...entry, text: scrubResult.text };
      }
    }
    return entry;
  });

  if (!anyRedacted) {
    return result;
  }
  return { ...record, content: scrubbed };
}

/**
 * Scrub secrets from an error text string.
 */
export function scrubErrorText(text: string, secrets: SecretValueSet): string {
  if (secrets.sortedValues.length === 0) {
    return text;
  }
  return scrubSecrets(text, secrets).text;
}
