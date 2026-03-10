import type { AgentToolResult } from "@mariozechner/pi-agent-core";
import { scrubToolResultContent, type SecretValueSet } from "../secrets/scrub.js";
import type { AnyAgentTool } from "./pi-tools.types.js";

/**
 * Wraps a tool's execute function to scrub secret values from the result
 * before it is stored in the agent's conversation history.
 *
 * This is the critical layer that prevents the model from seeing raw API keys,
 * tokens, and other credentials in tool output. Without this wrapper, scrubbing
 * only happens in the display/event layer while the model sees the original
 * unscrubbed result.
 */
export function wrapToolWithResultScrubbing(
  tool: AnyAgentTool,
  secretScrub: SecretValueSet,
): AnyAgentTool {
  if (secretScrub.sortedValues.length === 0) {
    return tool;
  }
  const execute = tool.execute;
  if (!execute) {
    return tool;
  }
  return {
    ...tool,
    execute: async (toolCallId, params, signal, onUpdate) => {
      const result = await execute(toolCallId, params, signal, onUpdate);
      // scrubToolResultContent preserves the result shape — cast back to the
      // expected return type since it only replaces text content values.
      return scrubToolResultContent(result, secretScrub) as AgentToolResult<unknown>;
    },
  };
}
