/**
 * Build a successful MCP tool response containing JSON-serialized data.
 */
export function mcpSuccess(data: unknown): { content: { type: 'text'; text: string }[] } {
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
  };
}

/**
 * Build a successful MCP tool response with pre-formatted markdown text.
 */
export function mcpFormatted(text: string): { content: { type: 'text'; text: string }[] } {
  return {
    content: [{ type: 'text', text }],
  };
}

/**
 * Build an MCP error response with a human-readable message.
 */
export function mcpError(
  message: string,
): { content: { type: 'text'; text: string }[]; isError: true } {
  return {
    content: [{ type: 'text', text: `Error: ${message}` }],
    isError: true,
  };
}
