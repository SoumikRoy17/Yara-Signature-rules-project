import { YaraRule, Pattern, YaraMatch } from './types';

export class YaraScanner {
  private decoder = new TextDecoder();

  private matchHexPattern(buffer: Uint8Array, pattern: Pattern): boolean {
    const hexString = Array.from(buffer)
      .map(byte => byte.toString(16).padStart(2, '0'))
      .join('')
      .toUpperCase();

    if (pattern.offset !== undefined) {
      const startPos = pattern.offset * 2; // 2 chars per byte in hex
      return hexString.slice(startPos).startsWith(pattern.value);
    }
    
    return hexString.includes(pattern.value);
  }

  private matchTextPattern(text: string, pattern: Pattern): boolean {
    return text.includes(pattern.value);
  }

  private matchRegexPattern(text: string, pattern: Pattern): boolean {
    const regex = new RegExp(pattern.value, 'i');
    return regex.test(text);
  }

  private async matchPattern(buffer: Uint8Array, pattern: Pattern): Promise<boolean> {
    const text = this.decoder.decode(buffer);

    switch (pattern.type) {
      case 'hex':
        return this.matchHexPattern(buffer, pattern);
      case 'text':
        return this.matchTextPattern(text, pattern);
      case 'regex':
        return this.matchRegexPattern(text, pattern);
      default:
        return false;
    }
  }

  public async scanBuffer(buffer: Uint8Array, rules: YaraRule[]): Promise<YaraMatch[]> {
    const matches: YaraMatch[] = [];

    for (const rule of rules) {
      const matchedPatterns: string[] = [];

      for (const pattern of rule.patterns) {
        if (await this.matchPattern(buffer, pattern)) {
          matchedPatterns.push(pattern.value);
        }
      }

      if (matchedPatterns.length > 0) {
        matches.push({
          ruleName: rule.name,
          description: rule.description,
          tags: rule.tags,
          matchedPatterns
        });
      }
    }

    return matches;
  }
}