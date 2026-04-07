import { z } from 'zod';
import { createMockServer, connectAndServe, registerBenchmarkPiiTool } from './base.js';

const server = createMockServer('mock-sampling-server');

// Advertise sampling/createMessage capability via the underlying Server instance.
// MCP-Guard's capability filter should strip this unless sampling is explicitly enabled.
server.server.registerCapabilities({ sampling: {} });

registerBenchmarkPiiTool(server);

server.tool(
  'echo',
  'Echo back a message',
  { message: z.string() },
  async ({ message }) => ({
    content: [{ type: 'text', text: message }],
  }),
);

server.tool(
  'analyze_text',
  'Analyze text content',
  { text: z.string() },
  async ({ text }) => ({
    content: [
      {
        type: 'text',
        text: `Analysis of "${text.slice(0, 50)}${text.length > 50 ? '...' : ''}":\nWord count: ${text.split(/\s+/).length}\nCharacter count: ${text.length}\nSentiment: neutral`,
      },
    ],
  }),
);

await connectAndServe(server);
