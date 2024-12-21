// File signature definitions and utilities
export const FILE_SIGNATURES = {
  'PDF': '25504446', // %PDF
  'PNG': '89504E47', // PNG
  'JPEG': 'FFD8FF',  // JPEG/JPG
  'ZIP': '504B0304', // ZIP
  'EXE': '4D5A',     // MZ
} as const;

export function getFileSignature(buffer: Uint8Array): string {
  return Array.from(buffer.slice(0, 8))
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

export function identifyFileFormat(signature: string): string | null {
  for (const [format, sig] of Object.entries(FILE_SIGNATURES)) {
    if (signature.startsWith(sig)) {
      return format;
    }
  }
  return null;
}