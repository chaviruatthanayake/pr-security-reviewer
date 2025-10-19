import { Rule, Finding } from './engine';

export const helmetRule: Rule = {
  id: 'SEC-003',
  name: 'Missing Security Headers',
  languages: ['javascript'],
  detector: (fileText: string, diffHunks: string, filename: string): Finding[] => {
    const findings: Finding[] = [];
    
    if (!/(server|app|index)\.(js|ts)$/i.test(filename)) {
      return findings;
    }

    const hasExpress = /require\s*\(\s*['"`]express['"`]\s*\)|from\s+['"`]express['"`]/i.test(fileText);
    if (!hasExpress) return findings;

    const hasHelmet = /require\s*\(\s*['"`]helmet['"`]\s*\)|from\s+['"`]helmet['"`]/i.test(fileText);
    const usesHelmet = /app\.use\s*\(\s*helmet\s*\(\s*\)\s*\)/i.test(fileText);

    if (!hasHelmet || !usesHelmet) {
      const lines = fileText.split('\n');
      let expressLine = 0;
      
      for (let i = 0; i < lines.length; i++) {
        if (/express\s*\(\s*\)/.test(lines[i])) {
          expressLine = i + 1;
          break;
        }
      }

      findings.push({
        ruleId: 'SEC-003',
        file: filename,
        line: expressLine || 1,
        severity: 'medium',
        message: 'Express app missing helmet security headers',
        suggestion: `**Why risky:** Without security headers, your app is vulnerable to XSS, clickjacking, and other attacks.

**How to fix:**
- Install helmet: \`npm install helmet\`
- Add it to your Express app

\`\`\`javascript
import helmet from 'helmet';
import express from 'express';

const app = express();
app.use(helmet()); // Add this line
\`\`\``,
      });
    }

    return findings;
  },
};
