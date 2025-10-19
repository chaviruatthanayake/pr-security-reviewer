import { Worker } from 'bullmq';
import { prisma } from './db';
import { getInstallationToken, getPRFiles, getFileContent, postReviewComments, createCheckRun } from './github';
import { runRules } from './rules/engine';

const worker = new Worker(
  'pr-scans',
  async (job) => {
    const { scanId, owner, repo, prNumber, headSha, installationId } = job.data;

    console.log(`Processing scan ${scanId} for ${owner}/${repo}#${prNumber}`);

    try {
      await prisma.scan.update({
        where: { id: scanId },
        data: { status: 'running' },
      });

      const token = await getInstallationToken(installationId);
      const changedFiles = await getPRFiles(token, owner, repo, prNumber);
      console.log(`Found ${changedFiles.length} changed files`);

      const allFindings: any[] = [];

      for (const file of changedFiles) {
        if (file.status === 'removed') continue;

        const content = await getFileContent(token, owner, repo, file.filename, headSha);
        if (!content) continue;

        const findings = runRules(file.filename, content, file.patch || '');
        
        for (const finding of findings) {
          const dbFinding = await prisma.finding.create({
            data: {
              scan_id: scanId,
              rule_id: finding.ruleId,
              file: file.filename,
              line: finding.line,
              severity: finding.severity,
              message: finding.message,
              suggestion_md: finding.suggestion,
              status: 'open',
            },
          });
          allFindings.push({ ...finding, id: dbFinding.id });
        }
      }

      console.log(`Found ${allFindings.length} total findings`);

      if (allFindings.length > 0) {
        await postReviewComments(token, owner, repo, prNumber, headSha, allFindings);
      }

      await createCheckRun(token, owner, repo, headSha, allFindings);

      await prisma.scan.update({
        where: { id: scanId },
        data: {
          status: 'completed',
          finished_at: new Date(),
        },
      });

      console.log(`Scan ${scanId} completed`);
    } catch (error: any) {
      console.error(`Scan ${scanId} failed:`, error.message);
      await prisma.scan.update({
        where: { id: scanId },
        data: {
          status: 'failed',
          finished_at: new Date(),
        },
      });
      throw error;
    }
  },
  {
    connection: {
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT || '6379'),
    },
  }
);

worker.on('completed', (job) => {
  console.log(`Job ${job.id} completed`);
});

worker.on('failed', (job, err) => {
  console.error(`Job ${job?.id} failed:`, err.message);
});

console.log('Worker started');
