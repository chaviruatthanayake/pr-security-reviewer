import { Rule, Finding } from './engine';

export const sqlInjectionRule: Rule = {
  id: 'SEC-002',
  name: 'SQL Injection Risk',
  languages: ['javascript'],
  detector: (fileText: string, diffHunks: string, filename: string): Finding[] => {
    const findings: Finding[] = [];
    const lines = fileText.split('\n');

    const sqlConcatPatterns = [
      /query\s*\(\s*['"`].*?\$\{.*?\}.*?['"`]\s*\)/g,
      /query\s*\(\s*['"`].*?\+.*?\+.*?['"`]\s*\)/g,
      /execute\s*\(\s*['"`].*?\$\{.*?\}.*?['"`]\s*\)/g,
      /execute\s*\(\s*['"`].*?\+.*?\+.*?['"`]\s*\)/g,
      /SELECT.*?\+.*?FROM/gi,
      /INSERT.*?\+.*?VALUES/gi,
      /UPDATE.*?\+.*?SET/gi,
      /DELETE.*?\+.*?FROM/gi,
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      for (const pattern of sqlConcatPatterns) {
        if (pattern.test(line)) {
          findings.push({
            ruleId: 'SEC-002',
            file: filename,
            line: i + 1,
            severity: 'high',
            message: 'SQL query with string concatenation detected',
            suggestion: `**Why risky:** Concatenating user input into SQL queries allows attackers to inject malicious SQL commands.

**How to fix:**
- Use parameterized queries or prepared statements
- Use an ORM (Prisma, TypeORM, Sequelize)
- Never interpolate variables directly into SQL strings

\`\`\`javascript
// ✅ Good - Parameterized query
db.query('SELECT * FROM users WHERE id = ?', [userId]);

// ❌ Bad - String concatenation
db.query(\`SELECT * FROM users WHERE id = \${userId}\`);
\`\`\``,
          });
          break;
        }
      }
    }

    return findings;
  },
};
