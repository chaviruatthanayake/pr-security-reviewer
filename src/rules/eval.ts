import { Rule, Finding } from './engine';

export const evalRule: Rule = {
  id: 'SEC-004',
  name: 'Dangerous Code Execution',
  languages: ['javascript'],
  detector: (fileText: string, diffHunks: string, filename: string): Finding[] => {
    const findings: Finding[] = [];
    const lines = fileText.split('\n');

    const dangerousPatterns = [
      { regex: /\beval\s*\(/g, name: 'eval()' },
      { regex: /new\s+Function\s*\(/g, name: 'new Function()' },
      { regex: /child_process\.exec\s*\(/g, name: 'child_process.exec()' },
      { regex: /require\s*\(\s*['"`]child_process['"`]\s*\)\.exec/g, name: 'child_process.exec()' },
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      for (const pattern of dangerousPatterns) {
        if (pattern.regex.test(line)) {
          findings.push({
            ruleId: 'SEC-004',
            file: filename,
            line: i + 1,
            severity: 'high',
            message: `Dangerous ${pattern.name} detected`,
            suggestion: `**Why risky:** ${pattern.name} can execute arbitrary code, enabling code injection attacks if user input is involved.

**How to fix:**
- Avoid dynamic code execution entirely
- Use safer alternatives
- If unavoidable, strictly validate and sanitize inputs
- Run in a sandboxed environment

\`\`\`javascript
// ✅ Good alternatives
// For child_process.exec:
const { execFile } = require('child_process');
execFile('command', ['arg1', 'arg2']);

// For eval: restructure your code to avoid it
\`\`\``,
          });
          break;
        }
      }
    }

    return findings;
  },
};
