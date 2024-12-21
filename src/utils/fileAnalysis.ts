import { generateSHA256Hash } from './hashGenerator';
import { generateMD5Hash } from './md5';
import { getFileSignature, identifyFileFormat } from './fileSignatures';
import { KNOWN_MALWARE_HASHES } from './malwareDatabase';
import { YaraScanner } from './yaraRules/scanner';
import { YARA_RULES } from './yaraRules/rules';
import { YaraMatch } from './yaraRules/types';

export interface FileSecurityInfo {
  md5Hash: string;
  sha256Hash: string;
  fileSignature: string;
  knownMalicious: boolean;
  malwareMatches: string[];
  yaraMatches: YaraMatch[];
}

export async function analyzeFileSecurity(file: File): Promise<FileSecurityInfo> {
  const arrayBuffer = await file.arrayBuffer();
  const buffer = new Uint8Array(arrayBuffer);
  
  // Generate file hashes
  const [sha256Hash, md5Hash] = await Promise.all([
    generateSHA256Hash(buffer),
    Promise.resolve(generateMD5Hash(buffer))
  ]);
  
  // Get file signature
  const fileSignature = getFileSignature(buffer);
  const detectedFormat = identifyFileFormat(fileSignature);
  
  // Check against known malware hashes
  const knownMalicious = KNOWN_MALWARE_HASHES.includes(sha256Hash);
  
  // Perform YARA scanning
  const scanner = new YaraScanner();
  const yaraMatches = await scanner.scanBuffer(buffer, YARA_RULES);
  
  return {
    md5Hash,
    sha256Hash,
    fileSignature: `${fileSignature} (${detectedFormat || 'Unknown'})`,
    knownMalicious,
    malwareMatches: knownMalicious ? ['Matched known malware hash'] : [],
    yaraMatches
  };
}