import React, { useState, useCallback } from 'react';
import { Shield, AlertTriangle, CheckCircle, FileWarning, Hash, FileSignature, Search, Tag } from 'lucide-react';
import { FileSecurityInfo, analyzeFileSecurity } from '../utils/fileAnalysis';
import { formatFileSize, isSuspiciousFile, getSuspiciousReasons } from '../utils/fileUtils';
import { YaraMatch } from '../utils/yaraRules/types';

interface AnalysisResult {
  fileName: string;
  fileSize: string;
  fileType: string;
  lastModified: string;
  suspicious: boolean;
  reasons: string[];
  securityInfo: FileSecurityInfo;
}

export function FileAnalyzer() {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [dragActive, setDragActive] = useState(false);

  const analyzeFile = async (file: File) => {
    setLoading(true);
    try {
      const securityInfo = await analyzeFileSecurity(file);
      const suspicious = isSuspiciousFile(file) || 
                        securityInfo.knownMalicious || 
                        securityInfo.yaraMatches.length > 0;
      
      setResult({
        fileName: file.name,
        fileSize: formatFileSize(file.size),
        fileType: file.type || 'Unknown',
        lastModified: new Date(file.lastModified).toLocaleString(),
        suspicious,
        reasons: [
          ...getSuspiciousReasons(file),
          ...securityInfo.malwareMatches,
          ...securityInfo.yaraMatches.map(match => 
            `YARA Rule Match: ${match.ruleName} - ${match.description}`)
        ],
        securityInfo
      });
    } catch (error) {
      console.error('File analysis failed:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      analyzeFile(e.dataTransfer.files[0]);
    }
  }, []);

  const handleFileInput = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      analyzeFile(e.target.files[0]);
    }
  }, []);

  const renderSecurityStatus = () => {
    if (!result) return null;
    return (
      <div className={`rounded-lg p-4 mb-4 ${result.suspicious ? 'bg-red-50' : 'bg-green-50'}`}>
        <div className="flex items-center">
          {result.suspicious ? (
            <AlertTriangle className="w-6 h-6 text-red-500 mr-2" />
          ) : (
            <CheckCircle className="w-6 h-6 text-green-500 mr-2" />
          )}
          <span className={`font-medium ${result.suspicious ? 'text-red-800' : 'text-green-800'}`}>
            {result.suspicious ? 'Suspicious File Detected' : 'File Appears Safe'}
          </span>
        </div>
        {result.reasons.length > 0 && (
          <ul className="mt-2 list-disc list-inside text-sm text-red-700">
            {result.reasons.map((reason, index) => (
              <li key={index}>{reason}</li>
            ))}
          </ul>
        )}
      </div>
    );
  };

  const renderFileInfo = () => {
    if (!result) return null;
    return (
      <div className="space-y-3">
        <div className="flex items-center">
          <FileWarning className="w-5 h-5 text-gray-500 mr-2" />
          <span className="font-medium">{result.fileName}</span>
        </div>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <p className="text-gray-600">Size</p>
            <p className="font-medium">{result.fileSize}</p>
          </div>
          <div>
            <p className="text-gray-600">Type</p>
            <p className="font-medium">{result.fileType}</p>
          </div>
          <div>
            <p className="text-gray-600">Last Modified</p>
            <p className="font-medium">{result.lastModified}</p>
          </div>
        </div>
      </div>
    );
  };

  const renderHashInfo = () => {
    if (!result) return null;
    return (
      <div className="mt-4 space-y-2">
        <div className="flex items-center">
          <Hash className="w-5 h-5 text-gray-500 mr-2" />
          <span className="font-medium">File Hashes</span>
        </div>
        <div className="text-sm space-y-1">
          <p>
            <span className="text-gray-600">MD5:</span>{' '}
            <code className="bg-gray-100 px-2 py-1 rounded">{result.securityInfo.md5Hash}</code>
          </p>
          <p>
            <span className="text-gray-600">SHA256:</span>{' '}
            <code className="bg-gray-100 px-2 py-1 rounded">{result.securityInfo.sha256Hash}</code>
          </p>
        </div>
      </div>
    );
  };

  const renderSignatureInfo = () => {
    if (!result) return null;
    return (
      <div className="mt-4">
        <div className="flex items-center">
          <FileSignature className="w-5 h-5 text-gray-500 mr-2" />
          <span className="font-medium">File Signature</span>
        </div>
        <p className="mt-1 text-sm">
          <code className="bg-gray-100 px-2 py-1 rounded">{result.securityInfo.fileSignature}</code>
        </p>
      </div>
    );
  };

  const renderYaraMatches = (matches: YaraMatch[]) => {
    if (matches.length === 0) return null;
    return (
      <div className="mt-4">
        <h3 className="text-lg font-medium mb-3 flex items-center">
          <Search className="w-5 h-5 text-gray-500 mr-2" />
          YARA Rule Matches
        </h3>
        <div className="space-y-4">
          {matches.map((match, index) => (
            <div key={index} className="bg-red-50 p-4 rounded-md">
              <h4 className="font-medium text-red-800">{match.ruleName}</h4>
              <p className="text-sm text-red-600 mt-1">{match.description}</p>
              <div className="flex flex-wrap gap-2 mt-2">
                {match.tags.map((tag, i) => (
                  <span key={i} className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-red-100 text-red-800">
                    <Tag className="w-3 h-3 mr-1" />
                    {tag}
                  </span>
                ))}
              </div>
              <div className="mt-2 text-sm text-red-700">
                <strong>Matched Patterns:</strong>
                <ul className="list-disc list-inside mt-1">
                  {match.matchedPatterns.map((pattern, i) => (
                    <li key={i}>{pattern}</li>
                  ))}
                </ul>
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  };

  return (
    <div className="max-w-4xl mx-auto p-6">
      <div className="text-center mb-8">
        <h1 className="text-3xl font-bold mb-2">File Security Scanner</h1>
        <p className="text-gray-600">
          Upload a file to analyze its security characteristics and detect potential threats
        </p>
      </div>

      <div
        className={`border-2 border-dashed rounded-lg p-8 mb-6 text-center ${
          dragActive ? 'border-blue-500 bg-blue-50' : 'border-gray-300'
        }`}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
      >
        <div className="flex flex-col items-center">
          <Shield className={`w-12 h-12 mb-4 ${dragActive ? 'text-blue-500' : 'text-gray-400'}`} />
          <p className="mb-2 text-lg">
            {dragActive ? 'Drop the file here' : 'Drag and drop a file here'}
          </p>
          <p className="text-gray-500 mb-4">or</p>
          <label className="cursor-pointer bg-blue-500 text-white px-4 py-2 rounded-lg hover:bg-blue-600 transition-colors">
            Select File
            <input
              type="file"
              className="hidden"
              onChange={handleFileInput}
              accept="*/*"
            />
          </label>
        </div>
      </div>

      {loading && (
        <div className="text-center py-12">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
          <p className="text-gray-600">Analyzing file...</p>
        </div>
      )}

      {result && !loading && (
        <div className="bg-white rounded-lg shadow-lg p-6">
          {renderSecurityStatus()}
          {renderFileInfo()}
          {renderHashInfo()}
          {renderSignatureInfo()}
          {renderYaraMatches(result.securityInfo.yaraMatches)}
        </div>
      )}
    </div>
  );
}