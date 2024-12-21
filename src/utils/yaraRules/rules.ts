import { YaraRule } from './types';

export const YARA_RULES: YaraRule[] = [
  {
    name: 'Suspicious_PE_Header',
    description: 'Detects suspicious PE file characteristics',
    tags: ['malicious', 'pe'],
    patterns: [
      { type: 'hex', value: '4D5A', offset: 0 }, // MZ header
      { type: 'text', value: 'This program cannot be run in DOS mode' }
    ]
  },
  {
    name: 'Potential_Ransomware',
    description: 'Detects common ransomware patterns',
    tags: ['malicious', 'ransomware'],
    patterns: [
      { type: 'text', value: 'Your files have been encrypted' },
      { type: 'text', value: 'bitcoin' },
      { type: 'text', value: 'decrypt' }
    ]
  },
  {
    name: 'Malicious_JavaScript',
    description: 'Detects potentially malicious JavaScript patterns',
    tags: ['malicious', 'javascript'],
    patterns: [
      { type: 'text', value: 'eval(atob' },
      { type: 'text', value: 'document.write(unescape' },
      { type: 'regex', value: '\\\\x[0-9a-fA-F]{2}' }
    ]
  },
  {
    name: 'Suspicious_PowerShell',
    description: 'Detects suspicious PowerShell commands',
    tags: ['suspicious', 'powershell'],
    patterns: [
      { type: 'text', value: '-enc ' },
      { type: 'text', value: 'IEX(' },
      { type: 'text', value: 'powershell.exe -w hidden' }
    ]
  }
];