import { z } from 'zod';
import { createMockServer, connectAndServe, registerBenchmarkPiiTool } from './base.js';

const server = createMockServer('mock-database');

server.tool(
  'query_sql',
  'Execute a SQL query and return results',
  { query: z.string() },
  async ({ query }) => ({
    content: [
      {
        type: 'text',
        text: `Query: ${query}\nResults:\n  id | name       | created_at\n  1  | benchmark  | 2024-01-01\n  2  | test       | 2024-01-02\n(2 rows)`,
      },
    ],
  }),
);

server.tool(
  'execute_sql',
  'Execute a SQL statement (INSERT, UPDATE, DELETE)',
  { query: z.string() },
  async ({ query }) => ({
    content: [{ type: 'text', text: `Executed: ${query}\nRows affected: 1` }],
  }),
);

server.tool(
  'create_table',
  'Create a new database table',
  { name: z.string(), columns: z.string() },
  async ({ name, columns }) => ({
    content: [{ type: 'text', text: `Created table "${name}" with columns: ${columns}` }],
  }),
);

server.tool(
  'drop_table',
  'Drop a database table',
  { name: z.string() },
  async ({ name }) => ({
    content: [{ type: 'text', text: `Dropped table "${name}"` }],
  }),
);

server.tool(
  'describe_table',
  'Describe the schema of a table',
  { name: z.string() },
  async ({ name }) => ({
    content: [
      {
        type: 'text',
        text: `Table: ${name}\n  id       INTEGER  PRIMARY KEY\n  name     TEXT     NOT NULL\n  created  DATETIME DEFAULT CURRENT_TIMESTAMP`,
      },
    ],
  }),
);

server.resource('schema', 'db://schema', async () => ({
  contents: [
    {
      uri: 'db://schema',
      text: JSON.stringify(
        {
          tables: [
            {
              name: 'users',
              columns: ['id', 'name', 'email', 'created_at'],
            },
            {
              name: 'sessions',
              columns: ['id', 'user_id', 'token', 'expires_at'],
            },
          ],
        },
        null,
        2,
      ),
    },
  ],
}));

registerBenchmarkPiiTool(server);

await connectAndServe(server);
