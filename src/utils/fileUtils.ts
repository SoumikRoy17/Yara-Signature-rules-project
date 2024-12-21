// Utility functions for file operations
export function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

export function isSuspiciousFile(file: File): boolean {
  const suspiciousExtensions = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js'];
  return suspiciousExtensions.some(ext => file.name.toLowerCase().endsWith(ext));
}

export function getSuspiciousReasons(file: File): string[] {
  const reasons: string[] = [];
  
  if (file.size > 100 * 1024 * 1024) { // 100MB
    reasons.push('File size exceeds 100MB');
  }
  
  if (isSuspiciousFile(file)) {
    reasons.push('Suspicious file extension');
  }
  
  return reasons;
}