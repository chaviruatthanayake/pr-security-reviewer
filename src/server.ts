import express from 'express';
import { Queue } from 'bullmq';
import { prisma } from './db';
import { verifyWebhookSignature } from './github';

const app = express();
app.use(express.json());

const scanQueue = new Queue('pr-scans', {
  connection: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379'),
  },
});

app.post('/github/webhook', async (req, res) => {
  const signature = req.headers['x-hub-signature-256'] as string;
  const event = req.headers['x-github-event'] as string;

  if (!verifyWebhookSignature(req.body, signature)) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  if (event !== 'pull_request') {
    return res.status(200).json({ message: 'Event ignored' });
  }

  const { action, pull_request, repository, installation } = req.body;

  if (!['opened', 'synchronize', 'reopened'].includes(action)) {
    return res.status(200).json({ message: 'Action ignored' });
  }

  const pr = pull_request;
  const repo = repository;

  let orgRecord = await prisma.org.findUnique({
    where: { installation_id: installation.id },
  });

  if (!orgRecord) {
    orgRecord = await prisma.org.create({
      data: {
        name: repo.owner.login,
        installation_id: installation.id,
      },
    });
  }

  let repoRecord = await prisma.repo.findUnique({
    where: { github_repo_id: repo.id },
  });

  if (!repoRecord) {
    repoRecord = await prisma.repo.create({
      data: {
        org_id: orgRecord.id,
        github_repo_id: repo.id,
        name: repo.name,
      },
    });
  }

  const scan = await prisma.scan.create({
    data: {
      repo_id: repoRecord.id,
      pr_number: pr.number,
      head_sha: pr.head.sha,
      status: 'pending',
      started_at: new Date(),
    },
  });

  await scanQueue.add('scan-pr', {
    scanId: scan.id,
    owner: repo.owner.login,
    repo: repo.name,
    prNumber: pr.number,
    headSha: pr.head.sha,
    installationId: installation.id,
  });

  res.status(202).json({ message: 'Scan queued', scanId: scan.id });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`API server running on port ${PORT}`);
});
