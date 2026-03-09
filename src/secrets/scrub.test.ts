import { describe, expect, it } from "vitest";
import {
  buildSecretValueSet,
  scrubErrorText,
  scrubSecrets,
  scrubToolResultContent,
} from "./scrub.js";

describe("buildSecretValueSet", () => {
  it("collects values from env vars matching blocked patterns", () => {
    const set = buildSecretValueSet({
      env: {
        OPENAI_API_KEY: "sk-test-1234567890abcdef",
        SAFE_VAR: "hello",
        PATH: "/usr/bin",
      },
    });
    expect(set.entries.has("OPENAI_API_KEY")).toBe(true);
    expect(set.entries.has("SAFE_VAR")).toBe(false);
    expect(set.entries.has("PATH")).toBe(false);
  });

  it("collects user-configured extra secret names", () => {
    const set = buildSecretValueSet({
      env: {
        MY_CUSTOM_TOKEN: "custom-secret-value-123",
      },
      extraSecretNames: ["MY_CUSTOM_TOKEN"],
    });
    expect(set.entries.has("MY_CUSTOM_TOKEN")).toBe(true);
  });

  it("skips values shorter than minLength", () => {
    const set = buildSecretValueSet({
      env: {
        OPENAI_API_KEY: "short",
      },
    });
    expect(set.entries.has("OPENAI_API_KEY")).toBe(false);
  });

  it("uses custom minLength", () => {
    const set = buildSecretValueSet({
      env: {
        OPENAI_API_KEY: "12345678",
      },
      minLength: 10,
    });
    expect(set.entries.has("OPENAI_API_KEY")).toBe(false);
  });

  it("sorts values by length descending", () => {
    const set = buildSecretValueSet({
      env: {
        SHORT_SECRET: "abcdefgh",
        LONG_SECRET: "abcdefghijklmnopqrstuvwxyz",
      },
    });
    expect(set.sortedValues[0][0]).toBe("LONG_SECRET");
    expect(set.sortedValues[1][0]).toBe("SHORT_SECRET");
  });

  it("returns empty set for no env", () => {
    const set = buildSecretValueSet({});
    expect(set.entries.size).toBe(0);
    expect(set.sortedValues.length).toBe(0);
  });

  it("matches catch-all pattern for _API_KEY suffix", () => {
    const set = buildSecretValueSet({
      env: {
        STRIPE_API_KEY: "sk_test_abc123456",
      },
    });
    expect(set.entries.has("STRIPE_API_KEY")).toBe(true);
  });

  it("matches catch-all pattern for _TOKEN suffix", () => {
    const set = buildSecretValueSet({
      env: {
        CUSTOM_TOKEN: "tok_abc123456",
      },
    });
    expect(set.entries.has("CUSTOM_TOKEN")).toBe(true);
  });

  it("matches catch-all pattern for _PASSWORD suffix", () => {
    const set = buildSecretValueSet({
      env: {
        DB_PASSWORD: "supersecretpassword123",
      },
    });
    expect(set.entries.has("DB_PASSWORD")).toBe(true);
  });
});

describe("scrubSecrets", () => {
  it("replaces known secret values with [REDACTED:name]", () => {
    const secrets = buildSecretValueSet({
      env: { OPENAI_API_KEY: "sk-test-1234567890" },
    });
    const result = scrubSecrets("The key is sk-test-1234567890 in the output", secrets);
    expect(result.text).toBe("The key is [REDACTED:OPENAI_API_KEY] in the output");
    expect(result.redacted).toBe(true);
    expect(result.redactedNames).toContain("OPENAI_API_KEY");
  });

  it("replaces multiple occurrences", () => {
    const secrets = buildSecretValueSet({
      env: { OPENAI_API_KEY: "sk-test-1234567890" },
    });
    const result = scrubSecrets("first: sk-test-1234567890 second: sk-test-1234567890", secrets);
    expect(result.text).toBe("first: [REDACTED:OPENAI_API_KEY] second: [REDACTED:OPENAI_API_KEY]");
  });

  it("uses longest-first replacement", () => {
    const secrets = buildSecretValueSet({
      env: {
        LONG_SECRET: "sk-test-1234567890-extended",
        SHORT_SECRET: "sk-test-1234567890",
      },
    });
    const result = scrubSecrets("value: sk-test-1234567890-extended", secrets);
    expect(result.text).toBe("value: [REDACTED:LONG_SECRET]");
  });

  it("detects base64-encoded values", () => {
    const plainValue = "sk-test-1234567890abcdef";
    const b64Value = Buffer.from(plainValue).toString("base64");
    const secrets = buildSecretValueSet({
      env: { OPENAI_API_KEY: plainValue },
    });
    const result = scrubSecrets(`encoded: ${b64Value}`, secrets);
    expect(result.text).toBe("encoded: [REDACTED:OPENAI_API_KEY]");
    expect(result.redacted).toBe(true);
  });

  it("returns unchanged text for empty secret set", () => {
    const secrets = buildSecretValueSet({});
    const result = scrubSecrets("nothing to scrub here", secrets);
    expect(result.text).toBe("nothing to scrub here");
    expect(result.redacted).toBe(false);
    expect(result.redactedNames).toEqual([]);
  });

  it("handles special regex characters in values", () => {
    const secrets = buildSecretValueSet({
      env: { WEIRD_SECRET: "value+with.special$chars" },
    });
    const result = scrubSecrets("found: value+with.special$chars end", secrets);
    expect(result.text).toBe("found: [REDACTED:WEIRD_SECRET] end");
  });

  it("handles multiple different secrets in one text", () => {
    const secrets = buildSecretValueSet({
      env: {
        API_KEY: "key-abc-123456",
        DB_PASSWORD: "pass-xyz-789012",
      },
    });
    const result = scrubSecrets("key=key-abc-123456 pass=pass-xyz-789012", secrets);
    expect(result.text).toBe("key=[REDACTED:API_KEY] pass=[REDACTED:DB_PASSWORD]");
    expect(result.redactedNames).toHaveLength(2);
  });
});

describe("scrubToolResultContent", () => {
  it("scrubs text blocks in tool result content", () => {
    const secrets = buildSecretValueSet({
      env: { OPENAI_API_KEY: "sk-test-1234567890" },
    });
    const result = scrubToolResultContent(
      {
        content: [{ type: "text", text: "key: sk-test-1234567890" }],
      },
      secrets,
    );
    const content = (result as { content: Array<{ text: string }> }).content;
    expect(content[0].text).toBe("key: [REDACTED:OPENAI_API_KEY]");
  });

  it("preserves non-text content blocks", () => {
    const secrets = buildSecretValueSet({
      env: { OPENAI_API_KEY: "sk-test-1234567890" },
    });
    const input = {
      content: [
        { type: "image", data: "base64data" },
        { type: "text", text: "safe text" },
      ],
    };
    const result = scrubToolResultContent(input, secrets);
    const content = (result as { content: unknown[] }).content;
    expect(content).toHaveLength(2);
    expect((content[0] as { type: string }).type).toBe("image");
  });

  it("returns unchanged result when no secrets match", () => {
    const secrets = buildSecretValueSet({
      env: { OPENAI_API_KEY: "sk-test-1234567890" },
    });
    const input = { content: [{ type: "text", text: "no secrets here" }] };
    const result = scrubToolResultContent(input, secrets);
    expect(result).toBe(input); // Same reference = no change.
  });

  it("returns unchanged for empty secret set", () => {
    const secrets = buildSecretValueSet({});
    const input = { content: [{ type: "text", text: "anything" }] };
    expect(scrubToolResultContent(input, secrets)).toBe(input);
  });

  it("handles non-object results", () => {
    const secrets = buildSecretValueSet({ env: { KEY: "value12345" } });
    expect(scrubToolResultContent(null, secrets)).toBeNull();
    expect(scrubToolResultContent("string", secrets)).toBe("string");
  });

  it("handles results without content array", () => {
    const secrets = buildSecretValueSet({ env: { KEY: "value12345" } });
    const input = { details: { status: "ok" } };
    expect(scrubToolResultContent(input, secrets)).toBe(input);
  });
});

describe("scrubErrorText", () => {
  it("scrubs secrets from error text", () => {
    const secrets = buildSecretValueSet({
      env: { OPENAI_API_KEY: "sk-test-1234567890" },
    });
    const result = scrubErrorText("Error: invalid key sk-test-1234567890", secrets);
    expect(result).toBe("Error: invalid key [REDACTED:OPENAI_API_KEY]");
  });

  it("returns unchanged text for empty set", () => {
    const secrets = buildSecretValueSet({});
    expect(scrubErrorText("safe error", secrets)).toBe("safe error");
  });
});
