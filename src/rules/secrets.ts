import { Rule, Finding } from './engine';

export const secretsRule: Rule = {
  id: 'SEC-001',
  name: 'Hardcoded Secrets',
  languages: ['javascript'],
  detector: (fileText: string, diffHunks: string, filename: string): Finding[] => {
    const findings: Finding[] = [];
    const lines = fileText.split('\n');

    const patterns = [
      {
        regex: /(['"`])AKIA[0-9A-Z]{16}\1/g,
        name: 'AWS Access Key',
      },
      {
        regex: /(['"`])ghp_[a-zA-Z0-9]{36}\1/g,
        name: 'GitHub Token',
      },
      {
        regex: /(['"`])sk-[a-zA-Z0-9]{48}\1/g,
        name: 'OpenAI API Key',
      },
      {
        regex: /(api[_-]?key|secret[_-]?key|private[_-]?key)\s*[:=]\s*['"`][a-zA-Z0-9_\-]{20,}['"`]/gi,
        name: 'Generic API Key',
      },
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      for (const pattern of patterns) {
        if (pattern.regex.test(line)) {
          findings.push({
            ruleId: 'SEC-001',
            file: filename,
            line: i + 1,
            severity: 'high',
            message: `${pattern.name} detected in code`,
            suggestion: `**Why risky:** Hardcoded secrets can be exposed in version control and logs.

**How to fix:**
- Store secrets in environment variables
- Use a secrets manager (AWS Secrets Manager, HashiCorp Vault)
- Add this file to .gitignore if it's a config file
- Rotate the exposed credential immediately

\`\`\`javascript
// ✅ Good
const apiKey = process.env.API_KEY;

// ❌ Bad
const apiKey = "AKIA1234567890ABCDEF";
\`\`\``,
          });
        }
      }
    }

    return findings;
  },
};
