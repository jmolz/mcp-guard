import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const server = new McpServer({
  name: 'mock-mcp-server',
  version: '1.0.0',
});

server.tool('echo', 'Echo back a message', { message: z.string() }, async ({ message }) => ({
  content: [{ type: 'text', text: message }],
}));

server.tool(
  'add',
  'Add two numbers',
  { a: z.number(), b: z.number() },
  async ({ a, b }) => ({
    content: [{ type: 'text', text: String(a + b) }],
  }),
);

server.resource('hello', 'test://hello', async () => ({
  contents: [{ uri: 'test://hello', text: 'Hello from mock server' }],
}));

server.resource('config', 'test://config', async () => ({
  contents: [
    {
      uri: 'test://config',
      text: JSON.stringify({ name: 'mock-mcp-server', version: '1.0.0' }),
    },
  ],
}));

const transport = new StdioServerTransport();
await server.connect(transport);
