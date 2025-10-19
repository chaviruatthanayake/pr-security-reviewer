import { secretsRule } from './secrets';
import { sqlInjectionRule } from './sql-injection';
import { helmetRule } from './helmet';
import { evalRule } from './eval';
import { csrfRule } from './csrf';

export interface Rule {
  id: string;
  name: string;
  languages: string[];
  detector: (fileText: string, diffHunks: string, filename: string) => Finding[];
}

export interface Finding {
  ruleId: string;
  file: string;
  line: number;
  severity: 'high' | 'medium' | 'low';
  message: string;
  suggestion: string;
}

const rules: Rule[] = [
  secretsRule,
  sqlInjectionRule,
  helmetRule,
  evalRule,
  csrfRule,
];

function getLanguageFromFilename(filename: string): string | null {
  const ext = filename.split('.').pop()?.toLowerCase();
  if (['js', 'jsx', 'ts', 'tsx'].includes(ext || '')) return 'javascript';
  if (ext === 'py') return 'python';
  return null;
}

function getChangedLineNumbers(patch: string): number[] {
  const lines: number[] = [];
  const hunkRegex = /@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/g;
  let match;
  
  while ((match = hunkRegex.exec(patch)) !== null) {
    const startLine = parseInt(match[1]);
    const lineCount = match[2] ? parseInt(match[2]) : 1;
    
    const hunkLines = patch.substring(match.index).split('\n');
    let currentLine = startLine;
    
    for (let i = 1; i < hunkLines.length; i++) {
      const line = hunkLines[i];
      if (!line) break;
      if (line.startsWith('@@')) break;
      
      if (line.startsWith('+') && !line.startsWith('+++')) {
        lines.push(currentLine);
        currentLine++;
      } else if (!line.startsWith('-')) {
        currentLine++;
      }
    }
  }
  
  return lines;
}

export function runRules(filename: string, fileText: string, patch: string): Finding[] {
  const language = getLanguageFromFilename(filename);
  if (!language) return [];

  const changedLines = getChangedLineNumbers(patch);
  if (changedLines.length === 0) return [];

  const findings: Finding[] = [];

  for (const rule of rules) {
    if (!rule.languages.includes(language)) continue;

    try {
      const ruleFindings = rule.detector(fileText, patch, filename);
      
      const filteredFindings = ruleFindings.filter(f => 
        changedLines.includes(f.line)
      );
      
      findings.push(...filteredFindings);
    } catch (error: any) {
      console.error(`Rule ${rule.id} failed:`, error.message);
    }
  }

  return findings;
}
