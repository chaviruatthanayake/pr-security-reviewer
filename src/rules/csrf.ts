import { Rule, Finding } from './engine';

export const csrfRule: Rule = {
  id: 'SEC-005',
  name: 'Missing CSRF Protection',
  languages: ['python'],
  detector: (fileText: string, diffHunks: string, filename: string): Finding[] => {
    const findings: Finding[] = [];
    
    const hasFlask = /from\s+flask\s+import|import\s+flask/i.test(fileText);
    if (!hasFlask) return findings;

    const hasCSRF = /from\s+flask_wtf\.csrf\s+import\s+CSRFProtect|CSRFProtect\s*\(/i.test(fileText);

    if (!hasCSRF) {
      const lines = fileText.split('\n');
      let flaskLine = 0;
      
      for (let i = 0; i < lines.length; i++) {
        if (/app\s*=\s*Flask/.test(lines[i])) {
          flaskLine = i + 1;
          break;
        }
      }

      findings.push({
        ruleId: 'SEC-005',
        file: filename,
        line: flaskLine || 1,
        severity: 'medium',
        message: 'Flask app missing CSRF protection',
        suggestion: `**Why risky:** Without CSRF protection, attackers can trick users into submitting malicious requests.

**How to fix:**
- Install Flask-WTF: \`pip install flask-wtf\`
- Enable CSRF protection globally

\`\`\`python
from flask import Flask
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
csrf = CSRFProtect(app)  # Add this
\`\`\``,
      });
    }

    return findings;
  },
};
