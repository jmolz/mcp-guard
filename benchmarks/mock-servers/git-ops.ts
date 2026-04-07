import { z } from 'zod';
import { createMockServer, connectAndServe, registerBenchmarkPiiTool } from './base.js';

const server = createMockServer('mock-git-ops');

server.tool(
  'git_clone',
  'Clone a git repository',
  { repo: z.string() },
  async ({ repo }) => ({
    content: [{ type: 'text', text: `Cloned ${repo} into ./repo` }],
  }),
);

server.tool(
  'git_push',
  'Push commits to a remote',
  { remote: z.string(), branch: z.string() },
  async ({ remote, branch }) => ({
    content: [{ type: 'text', text: `Pushed to ${remote}/${branch}\n1 commit transferred` }],
  }),
);

server.tool(
  'git_force_push',
  'Force push commits to a remote',
  { remote: z.string(), branch: z.string() },
  async ({ remote, branch }) => ({
    content: [{ type: 'text', text: `Force pushed to ${remote}/${branch}\n1 commit transferred (forced)` }],
  }),
);

server.tool(
  'git_delete_branch',
  'Delete a git branch',
  { branch: z.string() },
  async ({ branch }) => ({
    content: [{ type: 'text', text: `Deleted branch ${branch}` }],
  }),
);

server.tool(
  'git_create_pr',
  'Create a pull request',
  { title: z.string(), body: z.string() },
  async ({ title, body }) => ({
    content: [
      {
        type: 'text',
        text: `Created PR #42: "${title}"\nBody: ${body}\nURL: https://github.com/example/repo/pull/42`,
      },
    ],
  }),
);

server.tool('git_status', 'Show working tree status', {}, async () => ({
  content: [
    {
      type: 'text',
      text: 'On branch main\nYour branch is up to date with origin/main.\n\nnothing to commit, working tree clean',
    },
  ],
}));

server.resource('log', 'git://log', async () => ({
  contents: [
    {
      uri: 'git://log',
      text: 'commit abc1234 (HEAD -> main, origin/main)\nAuthor: Benchmark User <bench@example.com>\nDate:   Mon Jan 1 00:00:00 2024 +0000\n\n    Initial commit\n',
    },
  ],
}));

registerBenchmarkPiiTool(server);

await connectAndServe(server);
