import React, { useState } from 'react';
import { NetworkLogEntry, NetworkEventType, AppMode, EncryptedPayload, FileMetadata } from './types';
import NetworkLog from './components/NetworkLog';
import { 
  generateCEK, 
  generateKeyCode, 
  deriveKeyFromCode, 
  wrapCEK, 
  unwrapCEK, 
  encryptFileContent, 
  decryptFileContent,
  arrayBufferToBase64,
  base64ToArrayBuffer
} from './services/cryptoService';
import { Upload, Download, Shield, FileText, CheckCircle, Copy, AlertTriangle, RefreshCw, File as FileIcon, Lock, Unlock, FileJson } from 'lucide-react';

// Mock Server Storage (Optional backup, though we primarily use local files now)
const MOCK_DB: Record<string, EncryptedPayload> = {};

function App() {
  const [mode, setMode] = useState<AppMode>('UPLOAD');
  const [logs, setLogs] = useState<NetworkLogEntry[]>([]);
  
  // Upload State
  const [file, setFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState<{fileId: string, keyCode: string} | null>(null);
  const [encryptedBlobUrl, setEncryptedBlobUrl] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);

  // Decrypt State
  const [encryptedFileToDecrypt, setEncryptedFileToDecrypt] = useState<File | null>(null);
  const [decryptKey, setDecryptKey] = useState('');
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [decryptedFileUrl, setDecryptedFileUrl] = useState<string | null>(null);
  const [decryptedMeta, setDecryptedMeta] = useState<FileMetadata | null>(null);
  const [error, setError] = useState<string | null>(null);

  const addLog = (method: string, url: string, summary: string, encrypted: boolean = true) => {
    const entry: NetworkLogEntry = {
      id: crypto.randomUUID(),
      timestamp: new Date().toLocaleTimeString(),
      type: NetworkEventType.UPLOAD,
      method,
      url,
      payloadSummary: summary,
      isEncrypted: encrypted
    };
    setLogs(prev => [...prev, entry]);
  };

  const handleUpload = async () => {
    if (!file) return;
    setIsUploading(true);
    setProgress(10);
    setError(null);

    try {
      // 1. Generate Key Code and Salt
      const keyCode = generateKeyCode();
      const salt = window.crypto.getRandomValues(new Uint8Array(16));
      
      // 2. Derive Wrapping Key (Client-side only)
      const wrappingKey = await deriveKeyFromCode(keyCode, salt);
      
      // 3. Generate Content Key (CEK)
      const cek = await generateCEK();
      
      setProgress(30);

      // 4. Encrypt File
      const fileBuffer = await file.arrayBuffer();
      const { ciphertext, iv } = await encryptFileContent(fileBuffer, cek);
      
      setProgress(60);

      // 5. Wrap CEK
      const wrappedKey = await wrapCEK(cek, wrappingKey);

      // 6. Prepare Payload
      const fileId = crypto.randomUUID();
      const payload: EncryptedPayload = {
        metadata: {
          id: fileId,
          name: file.name,
          size: file.size,
          type: file.type,
          uploadedAt: Date.now()
        },
        iv: arrayBufferToBase64(iv.buffer as ArrayBuffer),
        salt: arrayBufferToBase64(salt.buffer as ArrayBuffer),
        encryptedCek: arrayBufferToBase64(wrappedKey),
        ciphertext: arrayBufferToBase64(ciphertext)
      };

      // 7. Create Downloadable Blob for the Encrypted File
      const jsonString = JSON.stringify(payload, null, 2);
      const blob = new Blob([jsonString], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      setEncryptedBlobUrl(url);

      // 8. Log "Network" Traffic (Simulating sending this blob or user downloading it)
      addLog('POST', '/api/v1/secure/storage', `
Headers:
  Content-Type: application/json
  X-Action: STORE_ENCRYPTED_BLOB

Body:
  {
    "file_id": "${fileId}",
    "iv_b64": "${payload.iv.substring(0, 10)}...",
    "key_wrap_b64": "${payload.encryptedCek.substring(0, 10)}...",
    "data_blob": "<${payload.ciphertext.length} bytes encrypted ciphertext>"
  }
      `);
      
      // Store in Mock DB as backup
      await new Promise(resolve => setTimeout(resolve, 800));
      MOCK_DB[fileId] = payload;

      setProgress(100);
      setUploadResult({ fileId, keyCode });
    } catch (err: any) {
      console.error(err);
      setError("Encryption failed: " + err.message);
    } finally {
      setIsUploading(false);
    }
  };

  const handleDecrypt = async () => {
    if (!encryptedFileToDecrypt || !decryptKey) return;
    setIsDecrypting(true);
    setError(null);
    setDecryptedFileUrl(null);

    try {
      addLog('LOCAL_READ', encryptedFileToDecrypt.name, 'Reading encrypted blob from disk...');
      
      // 1. Read Encrypted File
      const fileText = await encryptedFileToDecrypt.text();
      let payload: EncryptedPayload;
      
      try {
        payload = JSON.parse(fileText);
        if (!payload.iv || !payload.ciphertext || !payload.encryptedCek) {
          throw new Error("Invalid file format");
        }
      } catch (e) {
        throw new Error("Failed to parse encrypted file. Make sure you uploaded the correct .json file.");
      }

      await new Promise(resolve => setTimeout(resolve, 600)); // Simulate processing time

      addLog('PROCESS', 'DECRYPT_ATTEMPT', `
Payload Loaded:
  IV: ${payload.iv.substring(0, 10)}...
  Encrypted_CEK: ${payload.encryptedCek.substring(0, 10)}...
  Ciphertext_Size: ${payload.ciphertext.length} chars (Base64)
      `);

      // 2. Convert Base64 back to buffers
      const iv = new Uint8Array(base64ToArrayBuffer(payload.iv));
      const salt = new Uint8Array(base64ToArrayBuffer(payload.salt));
      const wrappedCekBuffer = base64ToArrayBuffer(payload.encryptedCek);
      const ciphertextBuffer = base64ToArrayBuffer(payload.ciphertext);

      // 3. Derive Unwrap Key from User Input Code
      const wrappingKey = await deriveKeyFromCode(decryptKey.trim(), salt);

      // 4. Unwrap CEK
      let cek: CryptoKey;
      try {
        cek = await unwrapCEK(wrappedCekBuffer, wrappingKey);
      } catch (e) {
        throw new Error("Invalid Key Code. Decryption rejected.");
      }

      // 5. Decrypt Content
      const plainBuffer = await decryptFileContent(ciphertextBuffer, iv, cek);

      // 6. Create Download Link
      const blob = new Blob([plainBuffer], { type: payload.metadata.type });
      const url = URL.createObjectURL(blob);
      
      setDecryptedFileUrl(url);
      setDecryptedMeta(payload.metadata);
      
      addLog('SUCCESS', 'DECRYPTION_COMPLETE', `Recovered: ${payload.metadata.name} (${payload.metadata.size} bytes)`);

    } catch (err: any) {
      console.error(err);
      addLog('ERROR', 'Decryption Failed', err.message, false);
      setError(err.message);
    } finally {
      setIsDecrypting(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    alert("Copied to clipboard!");
  };

  const resetUpload = () => {
    setFile(null);
    setUploadResult(null);
    setProgress(0);
    setEncryptedBlobUrl(null);
  };

  return (
    <div className="flex min-h-screen font-sans bg-vault-900 text-slate-200">
      
      {/* Main Content Area */}
      <div className="flex-1 flex flex-col mr-80 relative z-10">
        {/* Header */}
        <header className="h-16 border-b border-slate-700 bg-slate-900/50 backdrop-blur flex items-center justify-between px-8 sticky top-0 z-50">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-emerald-500 rounded-lg flex items-center justify-center shadow-lg shadow-emerald-500/20">
              <Shield className="text-white w-5 h-5" />
            </div>
            <h1 className="text-xl font-bold tracking-tight text-white">FileVault <span className="text-emerald-500 text-xs font-mono px-2 py-0.5 bg-emerald-500/10 rounded-full border border-emerald-500/20">SECURE</span></h1>
          </div>
          <nav className="flex gap-1 bg-slate-800 p-1 rounded-lg">
            <button 
              onClick={() => setMode('UPLOAD')}
              className={`px-4 py-1.5 rounded-md text-sm font-medium transition-all ${mode === 'UPLOAD' ? 'bg-slate-700 text-white shadow-sm' : 'text-slate-400 hover:text-white'}`}
            >
              Encrypt
            </button>
            <button 
              onClick={() => setMode('DECRYPT')}
              className={`px-4 py-1.5 rounded-md text-sm font-medium transition-all ${mode === 'DECRYPT' ? 'bg-slate-700 text-white shadow-sm' : 'text-slate-400 hover:text-white'}`}
            >
              Decrypt
            </button>
          </nav>
        </header>

        {/* Body */}
        <main className="flex-1 p-8 flex flex-col items-center justify-center">
          
          <div className="w-full max-w-2xl">
            {mode === 'UPLOAD' ? (
              <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
                <div className="text-center mb-8">
                  <h2 className="text-3xl font-bold text-white mb-2">Secure File Encryption</h2>
                  <p className="text-slate-400">Client-side AES-GCM encryption. Zero-knowledge architecture.</p>
                </div>

                {!uploadResult ? (
                  <div className="bg-slate-800/50 border border-slate-700 rounded-2xl p-8 backdrop-blur-sm relative overflow-hidden">
                    {isUploading && (
                       <div className="absolute top-0 left-0 h-1 bg-emerald-500 transition-all duration-300" style={{ width: `${progress}%` }}></div>
                    )}
                    
                    <div className="border-2 border-dashed border-slate-600 rounded-xl p-12 flex flex-col items-center justify-center transition-colors hover:border-emerald-500/50 hover:bg-slate-800 group">
                      <input 
                        type="file" 
                        id="fileInput"
                        className="hidden" 
                        onChange={(e) => setFile(e.target.files?.[0] || null)}
                      />
                      
                      {!file ? (
                        <label htmlFor="fileInput" className="cursor-pointer flex flex-col items-center w-full h-full">
                          <div className="w-16 h-16 bg-slate-700 rounded-full flex items-center justify-center mb-4 group-hover:scale-110 transition-transform">
                            <Upload className="w-8 h-8 text-slate-300 group-hover:text-emerald-400" />
                          </div>
                          <span className="text-lg font-medium text-slate-200">Click to select a file</span>
                          <span className="text-sm text-slate-500 mt-2">Any file type up to 50MB</span>
                        </label>
                      ) : (
                        <div className="flex flex-col items-center">
                          <FileText className="w-12 h-12 text-emerald-400 mb-4" />
                          <span className="text-lg font-medium text-white mb-1">{file.name}</span>
                          <span className="text-sm text-slate-400">{(file.size / 1024).toFixed(1)} KB</span>
                          <button 
                            onClick={() => setFile(null)}
                            className="text-xs text-red-400 mt-4 hover:underline"
                            disabled={isUploading}
                          >
                            Remove file
                          </button>
                        </div>
                      )}
                    </div>

                    <div className="mt-6 flex justify-end">
                       <button
                        onClick={handleUpload}
                        disabled={!file || isUploading}
                        className={`px-6 py-3 rounded-lg font-semibold flex items-center gap-2 ${
                          !file || isUploading 
                          ? 'bg-slate-700 text-slate-500 cursor-not-allowed' 
                          : 'bg-emerald-500 hover:bg-emerald-600 text-white shadow-lg shadow-emerald-500/20 active:scale-95 transition-all'
                        }`}
                       >
                         {isUploading ? (
                           <>
                            <RefreshCw className="animate-spin w-4 h-4" /> Encrypting...
                           </>
                         ) : (
                           <>
                            <Lock className="w-4 h-4" /> Encrypt File
                           </>
                         )}
                       </button>
                    </div>
                  </div>
                ) : (
                  <div className="bg-slate-800/50 border border-emerald-500/30 rounded-2xl p-8 backdrop-blur-sm animate-in zoom-in-95">
                    <div className="flex items-center gap-4 mb-6">
                      <div className="w-12 h-12 rounded-full bg-emerald-500/20 flex items-center justify-center">
                        <CheckCircle className="w-6 h-6 text-emerald-400" />
                      </div>
                      <div>
                        <h3 className="text-xl font-bold text-white">Encryption Successful</h3>
                        <p className="text-slate-400 text-sm">Download your encrypted file and save your key.</p>
                      </div>
                    </div>

                    <div className="bg-slate-900 rounded-lg p-6 border border-slate-700 mb-6">
                      <label className="text-xs text-slate-500 uppercase font-bold tracking-wider mb-2 block">1. Secret Key Code</label>
                      <div className="flex items-center gap-2">
                         <code className="flex-1 font-mono text-lg text-emerald-400 bg-slate-950 p-3 rounded border border-slate-800 overflow-hidden">
                           {uploadResult.keyCode}
                         </code>
                         <button 
                          onClick={() => copyToClipboard(uploadResult.keyCode)}
                          className="p-3 bg-slate-800 hover:bg-slate-700 rounded border border-slate-700 transition-colors"
                          title="Copy Key"
                         >
                           <Copy className="w-5 h-5 text-slate-300" />
                         </button>
                      </div>
                      <div className="flex items-center gap-2 mt-3 text-amber-400 text-xs bg-amber-400/10 p-2 rounded">
                        <AlertTriangle className="w-4 h-4" />
                        <span>Save this key! It is required to decrypt your file.</span>
                      </div>
                    </div>

                    <div className="bg-slate-900 rounded-lg p-6 border border-slate-700 mb-6">
                      <label className="text-xs text-slate-500 uppercase font-bold tracking-wider mb-2 block">2. Download Encrypted File</label>
                      <div className="flex items-center gap-3">
                         <div className="bg-slate-800 p-3 rounded border border-slate-700">
                           <FileJson className="w-6 h-6 text-slate-400" />
                         </div>
                         <div className="flex-1">
                           <div className="text-sm font-medium text-slate-300">{uploadResult.fileId}.vault.json</div>
                           <div className="text-xs text-slate-500">Contains encrypted data</div>
                         </div>
                         <a 
                           href={encryptedBlobUrl || '#'}
                           download={`encrypted-${uploadResult.fileId.substring(0,8)}.json`}
                           className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg font-medium flex items-center gap-2 transition-colors"
                         >
                           <Download className="w-4 h-4" /> Download
                         </a>
                      </div>
                    </div>

                    <button 
                      onClick={resetUpload}
                      className="w-full py-3 rounded-lg border border-slate-600 hover:bg-slate-800 text-slate-300 font-medium transition-all"
                    >
                      Encrypt Another File
                    </button>
                  </div>
                )}
              </div>
            ) : (
              <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
                <div className="text-center mb-8">
                  <h2 className="text-3xl font-bold text-white mb-2">Decrypt & Retrieve</h2>
                  <p className="text-slate-400">Upload your encrypted .json file and enter your Key Code.</p>
                </div>

                <div className="bg-slate-800/50 border border-slate-700 rounded-2xl p-8 backdrop-blur-sm">
                  
                  <div className="space-y-6 mb-6">
                    
                    {/* Encrypted File Input */}
                    <div>
                      <label className="block text-sm font-medium text-slate-300 mb-2">Encrypted File (.json)</label>
                      <div className="border border-dashed border-slate-600 rounded-lg p-6 flex flex-col items-center justify-center hover:bg-slate-800/50 transition-colors relative group">
                        <input 
                          type="file" 
                          accept=".json"
                          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                          onChange={(e) => setEncryptedFileToDecrypt(e.target.files?.[0] || null)}
                        />
                        {!encryptedFileToDecrypt ? (
                          <>
                            <FileJson className="w-8 h-8 text-slate-500 mb-2 group-hover:text-emerald-400" />
                            <span className="text-sm text-slate-400">Drop encrypted file here or click to upload</span>
                          </>
                        ) : (
                          <div className="flex items-center gap-3">
                            <FileJson className="w-8 h-8 text-emerald-400" />
                            <div className="text-left">
                              <div className="text-sm font-medium text-white">{encryptedFileToDecrypt.name}</div>
                              <div className="text-xs text-slate-400">{(encryptedFileToDecrypt.size / 1024).toFixed(1)} KB</div>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Key Code Input */}
                    <div>
                      <label className="block text-sm font-medium text-slate-300 mb-1">Key Code</label>
                      <div className="relative">
                        <input 
                          type="password" 
                          value={decryptKey}
                          onChange={(e) => setDecryptKey(e.target.value)}
                          placeholder="FV-XXXX-XXXX..."
                          className="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-3 text-white placeholder-slate-600 focus:ring-2 focus:ring-emerald-500 focus:border-transparent outline-none font-mono text-sm"
                        />
                        <Lock className="absolute right-3 top-3 w-5 h-5 text-slate-600" />
                      </div>
                    </div>
                  </div>

                  {error && (
                    <div className="mb-6 p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400 text-sm flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4" />
                      {error}
                    </div>
                  )}

                  {!decryptedFileUrl ? (
                    <button
                      onClick={handleDecrypt}
                      disabled={!encryptedFileToDecrypt || !decryptKey || isDecrypting}
                      className={`w-full py-3 rounded-lg font-semibold flex items-center justify-center gap-2 ${
                        !encryptedFileToDecrypt || !decryptKey || isDecrypting
                        ? 'bg-slate-700 text-slate-500 cursor-not-allowed' 
                        : 'bg-emerald-500 hover:bg-emerald-600 text-white shadow-lg shadow-emerald-500/20 active:scale-95 transition-all'
                      }`}
                    >
                      {isDecrypting ? (
                         <>
                          <RefreshCw className="animate-spin w-4 h-4" /> Decrypting...
                         </>
                       ) : (
                         <>
                          <Unlock className="w-4 h-4" /> Decrypt File
                         </>
                       )}
                    </button>
                  ) : (
                    <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-lg p-6 text-center animate-in zoom-in-95">
                      <FileIcon className="w-12 h-12 text-emerald-400 mx-auto mb-3" />
                      <h4 className="text-white font-medium text-lg mb-1">{decryptedMeta?.name}</h4>
                      <p className="text-slate-400 text-sm mb-4">Decryption verified. {(decryptedMeta?.size || 0) / 1024} KB</p>
                      
                      <div className="flex gap-3">
                         <a 
                          href={decryptedFileUrl} 
                          download={decryptedMeta?.name}
                          className="flex-1 bg-emerald-500 hover:bg-emerald-600 text-white py-2 rounded font-medium flex items-center justify-center gap-2 transition-colors"
                         >
                           <Download className="w-4 h-4" /> Download Original
                         </a>
                         <button 
                           onClick={() => {
                             setDecryptedFileUrl(null);
                             setDecryptKey('');
                             setEncryptedFileToDecrypt(null);
                           }}
                           className="px-4 border border-slate-600 rounded text-slate-300 hover:bg-slate-800"
                         >
                           Close
                         </button>
                      </div>
                    </div>
                  )}

                </div>
              </div>
            )}
          </div>
        </main>
        
        {/* Footer */}
        <footer className="p-6 border-t border-slate-800 text-center text-slate-600 text-sm">
          <p>© {new Date().getFullYear()} FileVault Secure Storage. Zero-Knowledge Proof-of-Concept.</p>
        </footer>
      </div>

      {/* Network Log Panel */}
      <NetworkLog logs={logs} />
    </div>
  );
}

export default App;