import { z } from 'zod';
import { createMockServer, connectAndServe, registerBenchmarkPiiTool } from './base.js';

const server = createMockServer('mock-filesystem');

server.tool(
  'read_file',
  'Read file contents',
  { path: z.string() },
  async ({ path }) => ({
    content: [{ type: 'text', text: `Contents of ${path}:\nSample file data for benchmark testing.` }],
  }),
);

server.tool(
  'write_file',
  'Write content to a file',
  { path: z.string(), content: z.string() },
  async ({ path, content }) => ({
    content: [{ type: 'text', text: `Wrote ${content.length} bytes to ${path}` }],
  }),
);

server.tool(
  'delete_file',
  'Delete a file',
  { path: z.string() },
  async ({ path }) => ({
    content: [{ type: 'text', text: `Deleted ${path}` }],
  }),
);

server.tool(
  'list_directory',
  'List directory contents',
  { path: z.string() },
  async ({ path }) => ({
    content: [
      {
        type: 'text',
        text: `Directory listing for ${path}:\n  README.md\n  src/\n  package.json\n  tsconfig.json`,
      },
    ],
  }),
);

server.tool(
  'search_files',
  'Search for files matching a pattern',
  { pattern: z.string(), path: z.string() },
  async ({ pattern, path }) => ({
    content: [
      {
        type: 'text',
        text: `Search results for "${pattern}" in ${path}:\n  src/index.ts\n  src/utils.ts`,
      },
    ],
  }),
);

server.resource('readme', 'file://readme', async () => ({
  contents: [
    {
      uri: 'file://readme',
      text: '# Sample Project\n\nThis is a sample README for benchmark testing.\n\n## Getting Started\n\nRun `npm install` to get started.',
    },
  ],
}));

registerBenchmarkPiiTool(server);

await connectAndServe(server);
