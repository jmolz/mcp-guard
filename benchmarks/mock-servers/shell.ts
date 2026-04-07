import { z } from 'zod';
import { createMockServer, connectAndServe, registerBenchmarkPiiTool } from './base.js';

const server = createMockServer('mock-shell');

server.tool(
  'run_command',
  'Run a shell command',
  { command: z.string() },
  async ({ command }) => ({
    content: [{ type: 'text', text: `$ ${command}\nCommand executed successfully.\nexit code: 0` }],
  }),
);

server.tool(
  'run_script',
  'Run a script with the specified interpreter',
  { script: z.string(), interpreter: z.string() },
  async ({ script, interpreter }) => ({
    content: [
      {
        type: 'text',
        text: `Ran script with ${interpreter}:\n---\n${script}\n---\nOutput: Script executed successfully.\nexit code: 0`,
      },
    ],
  }),
);

server.tool(
  'install_package',
  'Install a package using the specified package manager',
  { name: z.string(), manager: z.string() },
  async ({ name, manager }) => ({
    content: [
      {
        type: 'text',
        text: `${manager} install ${name}\nInstalled ${name}@1.0.0 successfully.`,
      },
    ],
  }),
);

registerBenchmarkPiiTool(server);

await connectAndServe(server);
