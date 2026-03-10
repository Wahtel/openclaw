import { describe, expect, it } from "vitest";
import { buildSecretValueSet, type SecretValueSet } from "../secrets/scrub.js";
import { wrapToolWithResultScrubbing } from "./pi-tools.result-scrub.js";
import type { AnyAgentTool } from "./pi-tools.types.js";

/** Build a minimal mock tool that returns the given result from execute. */
function mockTool(result: unknown): AnyAgentTool {
  return {
    name: "test_tool",
    label: "Test Tool",
    description: "A test tool",
    parameters: { type: "object", properties: {} },
    execute: async () => result,
  } as unknown as AnyAgentTool;
}

/** Build a SecretValueSet from a plain map of name→value pairs. */
function secrets(pairs: Record<string, string>): SecretValueSet {
  const entries = new Map(Object.entries(pairs));
  const sortedValues = [...entries.entries()].toSorted(([, a], [, b]) => b.length - a.length);
  return { entries, sortedValues };
}

/** Standard tool result shape with text content blocks. */
function textResult(text: string) {
  return {
    content: [{ type: "text", text }],
    details: {},
  };
}

describe("wrapToolWithResultScrubbing", () => {
  it("returns tool unchanged when sortedValues is empty", () => {
    const tool = mockTool(textResult("hello"));
    const empty: SecretValueSet = { entries: new Map(), sortedValues: [] };
    const wrapped = wrapToolWithResultScrubbing(tool, empty);
    // Should return the exact same reference (no wrapper overhead).
    expect(wrapped).toBe(tool);
  });

  it("scrubs secrets from text content blocks", async () => {
    const apiKey = "sk-test-1234567890abcdef";
    const tool = mockTool(textResult(`Your key is ${apiKey}`));
    const wrapped = wrapToolWithResultScrubbing(tool, secrets({ API_KEY: apiKey }));
    const result = (await wrapped.execute("call-1", {}, undefined, undefined)) as {
      content: { type: string; text: string }[];
    };
    expect(result.content[0].text).not.toContain(apiKey);
    expect(result.content[0].text).toContain("[REDACTED:API_KEY]");
  });

  it("leaves non-text content blocks unchanged", async () => {
    const apiKey = "sk-test-1234567890abcdef";
    const result = {
      content: [
        { type: "image", data: "base64data", media_type: "image/png" },
        { type: "text", text: `key: ${apiKey}` },
      ],
      details: {},
    };
    const tool = mockTool(result);
    const wrapped = wrapToolWithResultScrubbing(tool, secrets({ KEY: apiKey }));
    const output = (await wrapped.execute("call-1", {}, undefined, undefined)) as {
      content: { type: string; text?: string; data?: string }[];
    };
    // Image block preserved.
    expect(output.content[0]).toEqual({
      type: "image",
      data: "base64data",
      media_type: "image/png",
    });
    // Text block scrubbed.
    expect(output.content[1].text).toContain("[REDACTED:KEY]");
    expect(output.content[1].text).not.toContain(apiKey);
  });

  it("returns result as-is when it has no content array", async () => {
    const raw = { someField: "value" };
    const tool = mockTool(raw);
    const wrapped = wrapToolWithResultScrubbing(tool, secrets({ X: "irrelevant-secret-val" }));
    const output = await wrapped.execute("call-1", {}, undefined, undefined);
    expect(output).toEqual(raw);
  });

  it("handles null/undefined results", async () => {
    const tool = mockTool(null);
    const wrapped = wrapToolWithResultScrubbing(tool, secrets({ X: "irrelevant-secret-val" }));
    const output = await wrapped.execute("call-1", {}, undefined, undefined);
    expect(output).toBeNull();
  });

  it("scrubs multiple secrets in the same text block", async () => {
    const key1 = "sk-anthropic-key-abcdef1234";
    const key2 = "ghp_github-token-xyz9876";
    const text = `Anthropic: ${key1}\nGitHub: ${key2}`;
    const tool = mockTool(textResult(text));
    const wrapped = wrapToolWithResultScrubbing(
      tool,
      secrets({ ANTHROPIC_KEY: key1, GITHUB_TOKEN: key2 }),
    );
    const output = (await wrapped.execute("call-1", {}, undefined, undefined)) as {
      content: { type: string; text: string }[];
    };
    expect(output.content[0].text).not.toContain(key1);
    expect(output.content[0].text).not.toContain(key2);
    expect(output.content[0].text).toContain("[REDACTED:ANTHROPIC_KEY]");
    expect(output.content[0].text).toContain("[REDACTED:GITHUB_TOKEN]");
  });

  it("does not modify result when no secrets match text", async () => {
    const originalText = "No secrets here, just normal output.";
    const tool = mockTool(textResult(originalText));
    const wrapped = wrapToolWithResultScrubbing(
      tool,
      secrets({ KEY: "some-secret-not-in-output-12345" }),
    );
    const output = (await wrapped.execute("call-1", {}, undefined, undefined)) as {
      content: { type: string; text: string }[];
    };
    expect(output.content[0].text).toBe(originalText);
  });

  it("works end-to-end with buildSecretValueSet and auth-profile secrets", async () => {
    const apiKey = "sk-ant-api03-reallyLongApiKeyValue1234567890";
    const secretScrub = buildSecretValueSet({
      env: {},
      extraSecretValues: [{ name: "auth:anthropic", value: apiKey }],
    });
    const tool = mockTool(textResult(`The API key from auth-profiles.json is: ${apiKey}`));
    const wrapped = wrapToolWithResultScrubbing(tool, secretScrub);
    const output = (await wrapped.execute("call-1", {}, undefined, undefined)) as {
      content: { type: string; text: string }[];
    };
    expect(output.content[0].text).not.toContain(apiKey);
    expect(output.content[0].text).toContain("[REDACTED:auth:anthropic]");
  });
});
