import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

/** Example PII values that mock servers return for response-side PII testing. */
export const PII_RESPONSE_DATA = {
  email: 'victim@example.com',
  ssn: '123-45-6789',
  phone: '+1-555-123-4567',
  credit_card: '4111111111111111',
  aws_key: 'AKIAIOSFODNN7EXAMPLE',
  github_token: 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh',
} as const;

/** Create a new McpServer instance with the given name. */
export function createMockServer(name: string, version = '1.0.0'): McpServer {
  return new McpServer({ name, version });
}

/** Connect the server to stdio transport and serve. */
export async function connectAndServe(server: McpServer): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

/**
 * Register a `_benchmark_pii` tool that unconditionally returns all PII types.
 * Eliminates coupling between scenario generators and mock server trigger patterns.
 */
export function registerBenchmarkPiiTool(server: McpServer): void {
  server.tool('_benchmark_pii', 'Returns all PII types for benchmark testing', {}, async () => ({
    content: [
      {
        type: 'text',
        text: [
          `Email: ${PII_RESPONSE_DATA.email}`,
          `SSN: ${PII_RESPONSE_DATA.ssn}`,
          `Phone: ${PII_RESPONSE_DATA.phone}`,
          `Credit Card: ${PII_RESPONSE_DATA.credit_card}`,
          `AWS Key: ${PII_RESPONSE_DATA.aws_key}`,
          `GitHub Token: ${PII_RESPONSE_DATA.github_token}`,
        ].join('\n'),
      },
    ],
  }));
}
