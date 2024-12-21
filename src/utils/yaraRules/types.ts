export interface YaraRule {
  name: string;
  description: string;
  tags: string[];
  patterns: Pattern[];
}

export interface Pattern {
  type: 'hex' | 'text' | 'regex';
  value: string;
  offset?: number;
}

export interface YaraMatch {
  ruleName: string;
  description: string;
  tags: string[];
  matchedPatterns: string[];
}