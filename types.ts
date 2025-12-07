export interface FileMetadata {
  id: string;
  name: string;
  size: number;
  type: string;
  uploadedAt: number;
}

export interface EncryptedPayload {
  metadata: FileMetadata;
  iv: string; // Base64 encoded IV for file content
  salt: string; // Base64 encoded salt for key derivation
  encryptedCek: string; // Base64 encoded Wrapped Content Encryption Key
  ciphertext: string; // Base64 encoded file content (in real app, this would be a blob URL or S3 path)
}

export enum NetworkEventType {
  UPLOAD = 'UPLOAD',
  DOWNLOAD = 'DOWNLOAD',
  KEY_EXCHANGE = 'KEY_EXCHANGE',
  ERROR = 'ERROR'
}

export interface NetworkLogEntry {
  id: string;
  timestamp: string;
  type: NetworkEventType;
  method: string;
  url: string;
  payloadSummary: string;
  isEncrypted: boolean;
}

export type AppMode = 'UPLOAD' | 'DECRYPT';