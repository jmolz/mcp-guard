import { z } from 'zod';
import { createMockServer, connectAndServe, registerBenchmarkPiiTool } from './base.js';

const server = createMockServer('mock-api-client');

server.tool(
  'http_get',
  'Send an HTTP GET request',
  { url: z.string() },
  async ({ url }) => ({
    content: [
      {
        type: 'text',
        text: `GET ${url}\nStatus: 200 OK\nBody: {"status":"ok","data":"benchmark response"}`,
      },
    ],
  }),
);

server.tool(
  'http_post',
  'Send an HTTP POST request',
  { url: z.string(), body: z.string() },
  async ({ url, body }) => ({
    content: [
      {
        type: 'text',
        text: `POST ${url}\nRequest body: ${body}\nStatus: 201 Created\nBody: {"id":1,"created":true}`,
      },
    ],
  }),
);

server.tool(
  'http_put',
  'Send an HTTP PUT request',
  { url: z.string(), body: z.string() },
  async ({ url, body }) => ({
    content: [
      {
        type: 'text',
        text: `PUT ${url}\nRequest body: ${body}\nStatus: 200 OK\nBody: {"updated":true}`,
      },
    ],
  }),
);

server.tool(
  'http_delete',
  'Send an HTTP DELETE request',
  { url: z.string() },
  async ({ url }) => ({
    content: [{ type: 'text', text: `DELETE ${url}\nStatus: 204 No Content` }],
  }),
);

server.tool('list_endpoints', 'List available API endpoints', {}, async () => ({
  content: [
    {
      type: 'text',
      text: 'Available endpoints:\n  GET    /api/v1/users\n  POST   /api/v1/users\n  GET    /api/v1/users/:id\n  PUT    /api/v1/users/:id\n  DELETE /api/v1/users/:id',
    },
  ],
}));

server.resource('spec', 'api://spec', async () => ({
  contents: [
    {
      uri: 'api://spec',
      text: JSON.stringify(
        {
          openapi: '3.0.0',
          info: { title: 'Benchmark API', version: '1.0.0' },
          paths: {
            '/api/v1/users': {
              get: { summary: 'List users', responses: { '200': { description: 'OK' } } },
              post: { summary: 'Create user', responses: { '201': { description: 'Created' } } },
            },
          },
        },
        null,
        2,
      ),
    },
  ],
}));

registerBenchmarkPiiTool(server);

await connectAndServe(server);
