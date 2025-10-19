import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import axios from 'axios';

const GITHUB_API = 'https://api.github.com';

export function verifyWebhookSignature(payload: any, signature: string): boolean {
  const secret = process.env.WEBHOOK_SECRET!;
  const hmac = crypto.createHmac('sha256', secret);
  const digest = 'sha256=' + hmac.update(JSON.stringify(payload)).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(digest));
}

export async function getInstallationToken(installationId: number): Promise<string> {
  const appId = process.env.GITHUB_APP_ID!;
  const privateKey = process.env.GITHUB_PRIVATE_KEY!.replace(/\\n/g, '\n');

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iat: now - 60,
    exp: now + 600,
    iss: appId,
  };
  const token = jwt.sign(payload, privateKey, { algorithm: 'RS256' });

  const response = await axios.post(
    `${GITHUB_API}/app/installations/${installationId}/access_tokens`,
    {},
    {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github+json',
      },
    }
  );

  return response.data.token;
}

export async function getPRFiles(token: string, owner: string, repo: string, prNumber: number) {
  const response = await axios.get(
    `${GITHUB_API}/repos/${owner}/${repo}/pulls/${prNumber}/files`,
    {
      headers: {
        Authorization: `token ${token}`,
        Accept: 'application/vnd.github+json',
      },
    }
  );
  return response.data;
}

export async function getFileContent(
  token: string,
  owner: string,
  repo: string,
  path: string,
  ref: string
): Promise<string | null> {
  try {
    const response = await axios.get(
      `${GITHUB_API}/repos/${owner}/${repo}/contents/${path}?ref=${ref}`,
      {
        headers: {
          Authorization: `token ${token}`,
          Accept: 'application/vnd.github+json',
        },
      }
    );
    return Buffer.from(response.data.content, 'base64').toString('utf-8');
  } catch (error) {
    console.error(`Failed to fetch ${path}:`, error);
    return null;
  }
}

export async function postReviewComments(
  token: string,
  owner: string,
  repo: string,
  prNumber: number,
  commitSha: string,
  findings: any[]
) {
  // Post individual line comments instead of a review
  for (const finding of findings) {
    try {
      await axios.post(
        `${GITHUB_API}/repos/${owner}/${repo}/pulls/${prNumber}/comments`,
        {
          body: `**${finding.message}** (${finding.severity})\n\n${finding.suggestion}`,
          commit_id: commitSha,
          path: finding.file,
          line: finding.line,
        },
        {
          headers: {
            Authorization: `token ${token}`,
            Accept: 'application/vnd.github+json',
          },
        }
      );
      console.log(`Posted comment on ${finding.file}:${finding.line}`);
    } catch (error: any) {
      console.error(`Failed to post comment on ${finding.file}:${finding.line}:`, error.response?.data || error.message);
    }
  }
  
  console.log(`Posted ${findings.length} review comments`);
}
export async function createCheckRun(
  token: string,
  owner: string,
  repo: string,
  headSha: string,
  findings: any[]
) {
  const conclusion = findings.length > 0 ? 'neutral' : 'success';
  const summary =
    findings.length === 0
      ? '✅ No security issues found'
      : `⚠️ Found ${findings.length} potential security issue(s)`;

  let output = `### Security Scan Results\n\n`;
  if (findings.length > 0) {
    output += `| Rule | File:Line | Severity | Message |\n`;
    output += `|------|-----------|----------|----------|\n`;
    for (const f of findings) {
      output += `| ${f.ruleId} | \`${f.file}:${f.line}\` | ${f.severity} | ${f.message} |\n`;
    }
  }

  try {
    await axios.post(
      `${GITHUB_API}/repos/${owner}/${repo}/check-runs`,
      {
        name: 'Security Review',
        head_sha: headSha,
        status: 'completed',
        conclusion,
        output: {
          title: summary,
          summary: output,
        },
      },
      {
        headers: {
          Authorization: `token ${token}`,
          Accept: 'application/vnd.github+json',
        },
      }
    );
    console.log('Check run created');
  } catch (error: any) {
    console.error('Failed to create check run:', error.response?.data || error.message);
  }
}
