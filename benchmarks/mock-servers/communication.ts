import { z } from 'zod';
import { createMockServer, connectAndServe, registerBenchmarkPiiTool } from './base.js';

const server = createMockServer('mock-communication');

server.tool(
  'send_email',
  'Send an email message',
  { to: z.string(), subject: z.string(), body: z.string() },
  async ({ to, subject, body }) => ({
    content: [
      {
        type: 'text',
        text: `Email sent to ${to}\nSubject: ${subject}\nBody length: ${body.length} chars\nMessage-ID: <benchmark-001@example.com>`,
      },
    ],
  }),
);

server.tool(
  'send_slack_message',
  'Send a Slack message',
  { channel: z.string(), message: z.string() },
  async ({ channel, message }) => ({
    content: [
      {
        type: 'text',
        text: `Slack message sent to #${channel}\nMessage: ${message}\nTimestamp: 1704067200.000001`,
      },
    ],
  }),
);

server.tool(
  'send_webhook',
  'Send a webhook request',
  { url: z.string(), payload: z.string() },
  async ({ url, payload }) => ({
    content: [
      {
        type: 'text',
        text: `Webhook sent to ${url}\nPayload: ${payload}\nResponse: 200 OK`,
      },
    ],
  }),
);

server.tool('read_contacts', 'Read the contacts list', {}, async () => ({
  content: [
    {
      type: 'text',
      text: 'Contacts:\n  Alice Johnson (Engineering)\n  Bob Smith (Marketing)\n  Carol Williams (Design)\nTotal: 3 contacts',
    },
  ],
}));

registerBenchmarkPiiTool(server);

await connectAndServe(server);
