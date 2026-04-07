import { z } from 'zod';
import { createMockServer, connectAndServe, registerBenchmarkPiiTool } from './base.js';

const server = createMockServer('mock-cloud-infra');

server.tool(
  'deploy_service',
  'Deploy a service to an environment',
  { service: z.string(), env: z.string() },
  async ({ service, env }) => ({
    content: [
      {
        type: 'text',
        text: `Deployed ${service} to ${env}\nDeployment ID: deploy-bench-001\nStatus: running\nURL: https://${service}.${env}.example.com`,
      },
    ],
  }),
);

server.tool(
  'destroy_resource',
  'Destroy a cloud resource',
  { resource_id: z.string() },
  async ({ resource_id }) => ({
    content: [{ type: 'text', text: `Destroyed resource ${resource_id}\nStatus: terminated` }],
  }),
);

server.tool('list_instances', 'List running instances', {}, async () => ({
  content: [
    {
      type: 'text',
      text: 'Instances:\n  i-bench001  t3.medium  running  us-east-1a\n  i-bench002  t3.large   running  us-east-1b\n  i-bench003  t3.small   stopped  us-west-2a',
    },
  ],
}));

server.tool(
  'get_credentials',
  'Get credentials for a cloud service',
  { service: z.string() },
  async ({ service }) => ({
    content: [
      {
        type: 'text',
        text: `Credentials for ${service}:\nAccess Key: AKIABENCHMARK0EXAMPLE\nRegion: us-east-1\nExpires: 2024-12-31T23:59:59Z`,
      },
    ],
  }),
);

registerBenchmarkPiiTool(server);

await connectAndServe(server);
