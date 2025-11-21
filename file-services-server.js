
#!/usr/bin/env node
/**
 * Integrated File Services Server
 * Provides both file encryption and Azure upload services
 * 
 * Services:
 * - File Encryption Service (AES-256-CBC)
 * - Azure Blob Storage Upload Service
 * - File Processing Pipeline
 * 
 * Port: 3001 (configurable via PORT env variable)
 */

const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const { BlobServiceClient } = require('@azure/storage-blob');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');

// Load environment variables
try {
    require('dotenv').config();
} catch (error) {
    console.log('dotenv not available, using system environment variables');
}

// Configuration
const axios = require('axios');
const FormData = require('form-data');
const PORT = process.env.PORT || 3001;
const CONNECTION_STRING = process.env.CONNECTION_STRING || process.env.AZURE_STORAGE_CONNECTION_STRING;
const CONTAINER_NAME = process.env.CONTAINER_NAME || 'uploads';

// File Encryption Configuration
const ENCRYPTION_CONFIG = {
    algorithm: 'aes-256-cbc',
    keySize: 32, // 256 bits
    ivSize: 16,  // 128 bits
    masterKey: process.env.ENCRYPTION_MASTER_KEY || 'NIQ-FileManager-2025-SecureKey-AES256-Protection'
};

console.log('🚀 Starting Integrated File Services Server...');
console.log('================================================');

// Validate Azure configuration. If not present, offer a LOCAL_ONLY fallback for development/testing.
let blobServiceClient;
let containerClient;
let useLocalStorage = false;

if (!CONNECTION_STRING) {
    if (process.env.LOCAL_ONLY === 'true') {
        console.warn('⚠️ WARNING: Azure Storage connection string not found. Running in LOCAL_ONLY mode.');
        useLocalStorage = true;
    } else {
        console.error('❌ ERROR: Azure Storage connection string not found!');
        console.error('Please set CONNECTION_STRING environment variable or set LOCAL_ONLY=true for local testing.');
        process.exit(1);
    }
} else {
    try {
        console.log('🔵 Initializing Azure Blob Storage...');
        blobServiceClient = BlobServiceClient.fromConnectionString(CONNECTION_STRING);
        containerClient = blobServiceClient.getContainerClient(CONTAINER_NAME);
        console.log('✅ Azure Blob Storage client initialized');
        console.log(`📁 Container: ${CONTAINER_NAME}`);
    } catch (error) {
        console.error('❌ Failed to initialize Azure Blob Storage:', error.message);
        process.exit(1);
    }
}

// Initialize Express app
const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

// Configure multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage,
    limits: { 
        fileSize: 1024 * 1024 * 1024 // 1GB limit
    }
});

// ==========================================
// FILE ENCRYPTION SERVICE
// ==========================================

class FileEncryptionService {
    /**
     * Generate a unique encryption key for a file
     */
    static generateFileKey(fileName, timestamp) {
        const keySource = `${ENCRYPTION_CONFIG.masterKey}-${fileName}-${timestamp}`;
        return crypto.createHash('sha256').update(keySource).digest();
    }

    /**
     * Generate a random initialization vector
     */
    static generateIV() {
        return crypto.randomBytes(ENCRYPTION_CONFIG.ivSize);
    }

    /**
     * Calculate file checksum
     */
    static calculateChecksum(data) {
        return crypto.createHash('sha256').update(data).digest('hex');
    }

    /**
     * Check if file can be safely encrypted
     */
    static canEncryptFile(fileSizeBytes) {
        const fileSizeMB = fileSizeBytes / (1024 * 1024);
        const fileSizeGB = fileSizeMB / 1024;
        
        if (fileSizeGB > 2) {
            return {
                canEncrypt: false,
                reason: `File is extremely large (${fileSizeGB.toFixed(1)}GB)`,
                recommendation: 'Files over 2GB are not recommended for encryption due to processing time'
            };
        } else if (fileSizeMB > 1000) {
            return {
                canEncrypt: true,
                reason: `Very large file (${fileSizeMB.toFixed(0)}MB / ${fileSizeGB.toFixed(1)}GB)`,
                recommendation: 'Server-side encryption will take significant time',
                estimatedProcessingTime: `${Math.round(fileSizeMB / 50)} minutes`
            };
        } else if (fileSizeMB > 500) {
            return {
                canEncrypt: true,
                reason: `Large file (${fileSizeMB.toFixed(1)}MB)`,
                recommendation: 'Server-side encryption recommended for files this size',
                estimatedProcessingTime: `${Math.round(fileSizeMB / 100)} minutes`
            };
        } else if (fileSizeMB > 200) {
            return {
                canEncrypt: true,
                reason: `Medium-large file (${fileSizeMB.toFixed(1)}MB)`,
                recommendation: 'Server-side encryption is more efficient than client-side',
                estimatedProcessingTime: `${Math.round(fileSizeMB / 200)} minutes`
            };
        } else if (fileSizeMB > 100) {
            return {
                canEncrypt: true,
                reason: `Medium file (${fileSizeMB.toFixed(1)}MB)`,
                recommendation: 'Encryption will complete quickly on server',
                estimatedProcessingTime: 'Less than 1 minute'
            };
        }

        return { 
            canEncrypt: true,
            reason: 'File size optimal for encryption',
            estimatedProcessingTime: 'Less than 30 seconds'
        };
    }

    /**
     * Encrypt file content with chunked progress reporting
     */
    static encryptFile(fileBuffer, fileName) {
        try {
            const timestamp = Date.now();
            const fileKey = this.generateFileKey(fileName, timestamp);
            const iv = this.generateIV();
            
            console.log(`🔒 Starting encryption for: ${fileName} (${(fileBuffer.length / (1024 * 1024)).toFixed(2)}MB)`);
            
            // For large files, process in chunks for progress reporting
            const chunkSize = 1024 * 1024; // 1MB chunks for encryption progress
            const totalChunks = Math.ceil(fileBuffer.length / chunkSize);
            
            // Create cipher
            const cipher = crypto.createCipher(ENCRYPTION_CONFIG.algorithm, fileKey, { iv });
            
            // Encrypt the file content in chunks
            const encryptedChunks = [];
            
            if (totalChunks > 1) {
                console.log(`📊 Processing encryption in ${totalChunks} chunks...`);
                
                for (let i = 0; i < totalChunks; i++) {
                    const start = i * chunkSize;
                    const end = Math.min(start + chunkSize, fileBuffer.length);
                    const chunk = fileBuffer.slice(start, end);
                    
                    const encryptedChunk = cipher.update(chunk);
                    encryptedChunks.push(encryptedChunk);
                    
                    const progress = Math.round(((i + 1) / totalChunks) * 100);
                    console.log(`🔒 Encryption progress: ${progress}% (chunk ${i + 1}/${totalChunks})`);
                }
                
                // Final chunk
                encryptedChunks.push(cipher.final());
                console.log(`🔒 Encryption progress: 100% (finalized)`);
            } else {
                // Small file - encrypt in one go
                console.log(`🔒 Encrypting small file in single operation...`);
                encryptedChunks.push(cipher.update(fileBuffer));
                encryptedChunks.push(cipher.final());
                console.log(`🔒 Encryption progress: 100% (completed)`);
            }
            
            const encryptedContent = Buffer.concat(encryptedChunks);
            
            // Generate key ID for rotation support
            const keyId = crypto.createHash('md5').update(`${fileName}-${timestamp}`).digest('hex').substring(0, 8);
            
            // Calculate checksums
            const originalChecksum = this.calculateChecksum(fileBuffer);
            const encryptedChecksum = this.calculateChecksum(encryptedContent);
            
            // Create encrypted filename: filename + 'encrypted' + .extension
            const nameParts = fileName.split('.');
            const extension = nameParts.length > 1 ? nameParts.pop() : '';
            const baseName = nameParts.join('.');
            const encryptedName = extension ? `${baseName}encrypted.${extension}` : `${baseName}encrypted`;
            
            // Create metadata
            const metadata = {
                originalName: fileName,
                encryptedName: encryptedName,
                fileSize: fileBuffer.length,
                encryptedSize: encryptedContent.length,
                algorithm: ENCRYPTION_CONFIG.algorithm,
                timestamp: timestamp,
                checksum: originalChecksum,
                encryptedChecksum: encryptedChecksum,
                iv: iv.toString('hex'),
                keyId: keyId
            };

            console.log(`✅ File encrypted successfully: ${fileName} -> ${metadata.encryptedName} (${totalChunks} chunks processed)`);

            return {
                success: true,
                encryptedContent: encryptedContent,
                metadata: metadata
            };

        } catch (error) {
            console.error(`❌ Encryption failed for ${fileName}:`, error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Decrypt file content
     */
    static decryptFile(encryptedBuffer, metadata) {
        try {
            const fileKey = this.generateFileKey(metadata.originalName, metadata.timestamp);
            const iv = Buffer.from(metadata.iv, 'hex');
            
            // Create decipher
            const decipher = crypto.createDecipher(ENCRYPTION_CONFIG.algorithm, fileKey, { iv });
            
            // Decrypt the content
            const decryptedChunks = [];
            decryptedChunks.push(decipher.update(encryptedBuffer));
            decryptedChunks.push(decipher.final());
            
            const decryptedContent = Buffer.concat(decryptedChunks);
            
            // Verify checksum
            const checksum = this.calculateChecksum(decryptedContent);
            if (checksum !== metadata.checksum) {
                throw new Error('File integrity check failed - checksum mismatch');
            }

            console.log(`🔓 File decrypted successfully: ${metadata.encryptedName} -> ${metadata.originalName}`);

            return {
                success: true,
                decryptedContent: decryptedContent,
                originalName: metadata.originalName
            };

        } catch (error) {
            console.error(`❌ Decryption failed:`, error);
            return {
                success: false,
                error: error.message
            };
        }
    }
}

// ==========================================
// API ENDPOINTS
// ==========================================

/**
 * Health check endpoint
 */
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        services: {
            encryption: 'active',
            azure: 'connected',
            container: CONTAINER_NAME
        },
        timestamp: new Date().toISOString()
    });
});

/**
 * Check if file can be encrypted
 */
app.post('/encryption/check', (req, res) => {
    try {
        const { fileSize } = req.body;
        
        if (!fileSize) {
            return res.status(400).json({ 
                success: false, 
                error: 'File size is required' 
            });
        }

        const result = FileEncryptionService.canEncryptFile(fileSize);
        
        res.json({
            success: true,
            ...result
        });

    } catch (error) {
        console.error('Error checking encryption capability:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * Encrypt file endpoint
 */
app.post('/encryption/encrypt', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ 
                success: false, 
                error: 'No file provided' 
            });
        }

        const { originalname, buffer, size } = req.file;
        
        console.log(`🔒 Starting encryption for: ${originalname} (${(size / (1024 * 1024)).toFixed(2)}MB)`);

        // Check if file can be encrypted
        const canEncrypt = FileEncryptionService.canEncryptFile(size);
        if (!canEncrypt.canEncrypt) {
            return res.status(400).json({
                success: false,
                error: canEncrypt.reason,
                recommendation: canEncrypt.recommendation
            });
        }

        // Encrypt the file
        const encryptionResult = FileEncryptionService.encryptFile(buffer, originalname);
        
        if (!encryptionResult.success) {
            return res.status(500).json(encryptionResult);
        }

        res.json({
            success: true,
            metadata: encryptionResult.metadata,
            encryptedSize: encryptionResult.encryptedContent.length,
            // Note: We don't send the encrypted content back due to size
            // The client should call the upload endpoint with the encrypted flag
        });

    } catch (error) {
        console.error('Encryption endpoint error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * Upload file with optional encryption
 */
app.post('/upload', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ 
                success: false, 
                error: 'No file provided' 
            });
        }

        const { originalname, buffer, mimetype, size } = req.file;
        const { encrypt = 'false', metadata, uploader } = req.body;
        const shouldEncrypt = encrypt === 'true';
        
        // Parse metadata if provided
        let clientMetadata = {};
        if (metadata) {
            try {
                clientMetadata = JSON.parse(metadata);
            } catch (error) {
                console.warn('⚠️ Failed to parse metadata:', error);
            }
        }
        
        console.log(`📤 Processing upload: ${originalname} (${(size / (1024 * 1024)).toFixed(2)}MB) - Encrypt: ${shouldEncrypt}`);

        let uploadBuffer = buffer;
        let uploadMetadata = {
            originalName: clientMetadata.originalName || originalname,
            uploadDate: clientMetadata.uploadDate || new Date().toISOString(),
            fileSize: clientMetadata.fileSize || size.toString(),
            uploader: uploader || clientMetadata.uploader || req.body.uploader || 'API',
            contentType: clientMetadata.contentType || mimetype,
            category: clientMetadata.category || 'Other',
            folderPath: clientMetadata.folderPath || 'Unknown',
            fileCategory: clientMetadata.fileCategory || 'Other',
            ...clientMetadata // Include any additional metadata
        };

        // Encrypt file if requested and possible
        if (shouldEncrypt) {
            const canEncrypt = FileEncryptionService.canEncryptFile(size);
            if (canEncrypt.canEncrypt) {
                console.log(`🔒 Starting encryption process for file: ${originalname}`);
                console.log(`📊 File size: ${(size / (1024 * 1024)).toFixed(2)}MB`);
                
                const encryptionResult = FileEncryptionService.encryptFile(buffer, originalname);
                
                if (encryptionResult.success) {
                    uploadBuffer = encryptionResult.encryptedContent;
                    uploadMetadata = {
                        ...uploadMetadata,
                        encrypted: 'true',
                        encryptionAlgorithm: encryptionResult.metadata.algorithm,
                        encryptionKeyId: encryptionResult.metadata.keyId,
                        encryptionTimestamp: encryptionResult.metadata.timestamp.toString(),
                        originalChecksum: encryptionResult.metadata.checksum,
                        encryptedSize: encryptionResult.metadata.encryptedSize.toString(),
                        encryptedName: encryptionResult.metadata.encryptedName
                    };
                    console.log(`✅ Encryption completed - proceeding to upload encrypted file`);
                } else {
                    console.warn(`⚠️ Encryption failed: ${encryptionResult.error} - uploading without encryption`);
                }
            } else {
                console.log(`📝 File too large for encryption (${canEncrypt.reason}) - uploading without encryption`);
            }
        }

        // Use the blob name from client metadata or fallback to originalname
        const blobName = clientMetadata.blobName || originalname;
        console.log(`📁 Using blob name: ${blobName}`);

        let resultUrl = null;

        if (useLocalStorage) {
            // Ensure local uploads directory exists
            const uploadsDir = path.join(process.cwd(), 'local_uploads');
            await fs.mkdir(uploadsDir, { recursive: true });

            const safeName = blobName.replace(/[^a-zA-Z0-9_.-]/g, '_');
            const filePath = path.join(uploadsDir, safeName);
            await fs.writeFile(filePath, uploadBuffer);

            resultUrl = `file://${filePath}`;
            console.log(`💾 Saved upload locally: ${filePath}`);
        } else {
            // Upload to Azure Blob Storage
            console.log(`☁️ Uploading to Azure Blob Storage: ${blobName}`);
            const blockBlobClient = containerClient.getBlockBlobClient(blobName);
            
            await blockBlobClient.upload(uploadBuffer, uploadBuffer.length, {
                metadata: uploadMetadata,
                blobHTTPHeaders: {
                    blobContentType: uploadMetadata.encrypted ? 'application/octet-stream' : mimetype
                }
            });

            resultUrl = blockBlobClient.url;
            console.log(`✅ Upload completed: ${blobName}`);
        }

        res.json({
            success: true,
            url: resultUrl,
            blobName: blobName,
            metadata: uploadMetadata,
            encrypted: uploadMetadata.encrypted === 'true',
            size: uploadBuffer.length
        });

    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * Upload large file with chunking support
 */
app.post('/upload-chunk', upload.single('chunk'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ 
                success: false, 
                error: 'No chunk provided' 
            });
        }

        const { buffer } = req.file;
        const { fileName, blockId, chunkIndex } = req.body;

        if (!fileName || !blockId) {
            return res.status(400).json({ 
                success: false, 
                error: 'fileName and blockId are required' 
            });
        }

        const chunkSizeMB = (buffer.length / (1024 * 1024)).toFixed(2);
        console.log(`📦 Processing chunk ${chunkIndex} for ${fileName} (${chunkSizeMB}MB)`);

        // Upload chunk to Azure
        const blockBlobClient = containerClient.getBlockBlobClient(fileName);
        
        console.log(`☁️ Staging chunk ${chunkIndex} to Azure Blob Storage...`);
        await blockBlobClient.stageBlock(blockId, buffer, buffer.length);

        console.log(`✅ Chunk ${chunkIndex} staged successfully (${chunkSizeMB}MB transferred)`);

        res.json({
            success: true,
            chunkIndex: parseInt(chunkIndex),
            blockId: blockId,
            chunkSize: buffer.length
        });

    } catch (error) {
        console.error('Chunk upload error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * Finalize chunked upload
 */
app.post('/finalize-upload', async (req, res) => {
    try {
        const { fileName, blockIds, metadata } = req.body;

        if (!fileName || !blockIds || !Array.isArray(blockIds)) {
            return res.status(400).json({ 
                success: false, 
                error: 'fileName and blockIds array are required' 
            });
        }

        console.log(`🔗 Finalizing chunked upload for ${fileName} (${blockIds.length} chunks)`);
        console.log(`📋 Block IDs to commit: [${blockIds.slice(0, 3).join(', ')}${blockIds.length > 3 ? '...' : ''}]`);

        // Use blobName from metadata if provided, otherwise use fileName
        const blobName = metadata?.blobName || fileName;

        // Commit the blocks
        const blockBlobClient = containerClient.getBlockBlobClient(blobName);
        
        console.log(`☁️ Committing ${blockIds.length} blocks to Azure Blob Storage...`);
        await blockBlobClient.commitBlockList(blockIds, {
            metadata: metadata || {},
            blobHTTPHeaders: {
                blobContentType: metadata?.contentType || 'application/octet-stream'
            }
        });

        const azureUrl = blockBlobClient.url;
        
        console.log(`✅ Chunked upload finalized: ${blobName} (${blockIds.length} chunks committed successfully)`);

        res.json({
            success: true,
            url: azureUrl,
            fileName: blobName,
            totalChunks: blockIds.length
        });

    } catch (error) {
        console.error('Finalize upload error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * Finalize chunked upload with post-encryption
 */
app.post('/finalize-upload-with-encryption', async (req, res) => {
    try {
        const { fileName, blockIds, metadata } = req.body;

        if (!fileName || !blockIds || !Array.isArray(blockIds)) {
            return res.status(400).json({ 
                success: false, 
                error: 'fileName and blockIds array are required' 
            });
        }

        console.log(`🔗 Finalizing chunked upload with encryption for ${fileName} (${blockIds.length} chunks)`);
        console.log(`📋 Block IDs to commit: [${blockIds.slice(0, 3).join(', ')}${blockIds.length > 3 ? '...' : ''}]`);

        // Use blobName from metadata if provided, otherwise use fileName
        const blobName = metadata?.blobName || fileName;

        // First, commit the blocks to create the complete file
        const blockBlobClient = containerClient.getBlockBlobClient(blobName);
        
        console.log(`☁️ Committing ${blockIds.length} blocks to Azure Blob Storage...`);
        await blockBlobClient.commitBlockList(blockIds, {
            metadata: metadata || {},
            blobHTTPHeaders: {
                blobContentType: metadata?.contentType || 'application/octet-stream'
            }
        });

        console.log(`✅ Chunks committed successfully, now downloading for encryption...`);

        // Download the complete file for encryption
        const downloadResponse = await blockBlobClient.download();
        const chunks = [];
        for await (const chunk of downloadResponse.readableStreamBody) {
            chunks.push(chunk);
        }
        const completeFileBuffer = Buffer.concat(chunks);
        
        console.log(`📥 Downloaded complete file for encryption (${(completeFileBuffer.length / (1024 * 1024)).toFixed(2)}MB)`);

        // Check if file can be encrypted
        const canEncrypt = FileEncryptionService.canEncryptFile(completeFileBuffer.length);
        if (!canEncrypt.canEncrypt) {
            console.log(`⚠️ File cannot be encrypted: ${canEncrypt.reason}`);
            return res.json({
                success: true,
                url: blockBlobClient.url,
                fileName: fileName,
                totalChunks: blockIds.length,
                encrypted: false,
                reason: canEncrypt.reason
            });
        }

        // Encrypt the complete file
        console.log(`🔒 Starting post-upload encryption for ${fileName}...`);
        const encryptionResult = FileEncryptionService.encryptFile(completeFileBuffer, fileName);
        
        if (!encryptionResult.success) {
            console.error(`❌ Post-upload encryption failed: ${encryptionResult.error}`);
            return res.json({
                success: true,
                url: blockBlobClient.url,
                fileName: fileName,
                totalChunks: blockIds.length,
                encrypted: false,
                encryptionError: encryptionResult.error
            });
        }

        // Generate new encrypted blob name with folder structure
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        // For encrypted files, use the folder path from the original blobName plus the encrypted filename
        const folderPath = blobName.includes('/') ? blobName.substring(0, blobName.lastIndexOf('/') + 1) : '';
        const encryptedBlobName = `${folderPath}${encryptionResult.metadata.encryptedName}`;
        
        console.log(`📤 Uploading encrypted version: ${encryptedBlobName}`);
        
        // Upload encrypted version
        const encryptedBlobClient = containerClient.getBlockBlobClient(encryptedBlobName);
        await encryptedBlobClient.upload(encryptionResult.encryptedContent, encryptionResult.encryptedContent.length, {
            metadata: {
                ...metadata,
                encrypted: 'true',
                encryptionAlgorithm: encryptionResult.metadata.algorithm,
                encryptionKeyId: encryptionResult.metadata.keyId,
                encryptionTimestamp: encryptionResult.metadata.timestamp.toString(),
                originalChecksum: encryptionResult.metadata.checksum,
                encryptedSize: encryptionResult.metadata.encryptedSize.toString(),
                encryptedName: encryptionResult.metadata.encryptedName,
                originalName: encryptionResult.metadata.originalName
            },
            blobHTTPHeaders: {
                blobContentType: 'application/octet-stream'
            }
        });

        // Delete the original unencrypted file
        console.log(`🗑️ Deleting original unencrypted file: ${blobName}`);
        await blockBlobClient.deleteIfExists();

        const encryptedUrl = encryptedBlobClient.url;
        
        console.log(`✅ Chunked upload with encryption completed: ${encryptedBlobName}`);

        res.json({
            success: true,
            url: encryptedUrl,
            fileName: encryptedBlobName,
            originalFileName: blobName,
            totalChunks: blockIds.length,
            encrypted: true,
            encryptionMetadata: encryptionResult.metadata
        });

    } catch (error) {
        console.error('Finalize upload with encryption error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * Decrypt and download file
 */
app.get('/decrypt/:blobName', async (req, res) => {
    try {
        const { blobName } = req.params;
        
        console.log(`🔓 Decryption request for: ${blobName}`);

        // Download from Azure
        const blockBlobClient = containerClient.getBlockBlobClient(blobName);
        const downloadResponse = await blockBlobClient.download();
        
        // Get metadata
        const properties = await blockBlobClient.getProperties();
        const azureMetadata = properties.metadata;

        if (azureMetadata.encrypted !== 'true') {
            return res.status(400).json({
                success: false,
                error: 'File is not encrypted'
            });
        }

        // Read the encrypted content
        const chunks = [];
        for await (const chunk of downloadResponse.readableStreamBody) {
            chunks.push(chunk);
        }
        const encryptedBuffer = Buffer.concat(chunks);

        // Prepare decryption metadata
        const decryptionMetadata = {
            originalName: azureMetadata.originalName,
            timestamp: parseInt(azureMetadata.encryptionTimestamp),
            checksum: azureMetadata.originalChecksum,
            iv: azureMetadata.encryptionIv || '', // This might need to be stored separately
            algorithm: azureMetadata.encryptionAlgorithm
        };

        // Decrypt the file
        const decryptionResult = FileEncryptionService.decryptFile(encryptedBuffer, decryptionMetadata);

        if (!decryptionResult.success) {
            return res.status(500).json({
                success: false,
                error: decryptionResult.error
            });
        }

        // Send the decrypted file
        res.setHeader('Content-Disposition', `attachment; filename="${decryptionResult.originalName}"`);
        res.setHeader('Content-Type', 'application/octet-stream');
        res.send(decryptionResult.decryptedContent);

        console.log(`✅ File decrypted and sent: ${decryptionResult.originalName}`);

    } catch (error) {
        console.error('Decryption error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// ==========================================
// LEGACY ENDPOINTS (for backward compatibility)
// ==========================================

/**
 * Legacy commit blocks endpoint (for old AzureUploader)
 */
app.post('/commit-blocks', async (req, res) => {
    try {
        const { fileName, blockIds, contentType, metadata } = req.body;

        if (!fileName || !blockIds || !Array.isArray(blockIds)) {
            return res.status(400).json({ 
                success: false, 
                error: 'fileName and blockIds array are required' 
            });
        }

        console.log(`🔗 Legacy commit blocks for ${fileName} (${blockIds.length} chunks)`);

        // Commit the blocks using Azure SDK
        const blockBlobClient = containerClient.getBlockBlobClient(fileName);
        await blockBlobClient.commitBlockList(blockIds, {
            metadata: metadata || {},
            blobHTTPHeaders: {
                blobContentType: contentType || 'application/octet-stream'
            }
        });

        const azureUrl = blockBlobClient.url;
        
        console.log(`✅ Legacy commit blocks completed: ${fileName}`);

        res.json({
            success: true,
            url: azureUrl,
            fileName: fileName,
            totalChunks: blockIds.length
        });

    } catch (error) {
        console.error('Legacy commit blocks error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * Legacy upload chunk endpoint (for old AzureUploader)
 */
app.post('/upload-to-azure', upload.single('chunk'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ 
                success: false, 
                error: 'No chunk provided' 
            });
        }

        const { buffer } = req.file;
        const { fileName, blockId, chunkIndex } = req.body;

        if (!fileName || !blockId) {
            return res.status(400).json({ 
                success: false, 
                error: 'fileName and blockId are required' 
            });
        }

        console.log(`📦 Legacy chunk upload ${chunkIndex} for ${fileName} (${buffer.length} bytes)`);

        // Upload chunk to Azure
        const blockBlobClient = containerClient.getBlockBlobClient(fileName);
        await blockBlobClient.stageBlock(blockId, buffer, buffer.length);

        console.log(`✅ Legacy chunk ${chunkIndex} uploaded successfully`);

        res.json({
            success: true,
            chunkIndex: parseInt(chunkIndex),
            blockId: blockId,
            chunkSize: buffer.length
        });

    } catch (error) {
        console.error('Legacy chunk upload error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// ==========================================
// SERVER STARTUP
// ==========================================

// Start server
app.listen(PORT, () => {
    console.log('');
    console.log('🎉 Integrated File Services Server Started!');
    console.log('============================================');
    console.log(`🚀 Server running on: http://localhost:${PORT}`);
    console.log(`📁 Azure Container: ${CONTAINER_NAME}`);
    console.log(`🔒 Encryption: AES-256-CBC`);
    console.log('');
    console.log('📋 Available Endpoints:');
    console.log(`   • Health Check: http://localhost:${PORT}/health`);
    console.log(`   • Encryption Check: http://localhost:${PORT}/encryption/check`);
    console.log(`   • Encrypt File: http://localhost:${PORT}/encryption/encrypt`);
    console.log(`   • Upload File: http://localhost:${PORT}/upload`);
    console.log(`   • Upload Chunk: http://localhost:${PORT}/upload-chunk`);
    console.log(`   • Finalize Upload: http://localhost:${PORT}/finalize-upload`);
    console.log(`   • Finalize Upload with Encryption: http://localhost:${PORT}/finalize-upload-with-encryption`);
    console.log(`   • Decrypt File: http://localhost:${PORT}/decrypt/:blobName`);
    console.log(`   • Legacy Commit Blocks: http://localhost:${PORT}/commit-blocks`);
    console.log(`   • Legacy Upload: http://localhost:${PORT}/upload-to-azure`);
    console.log('');
    console.log('✅ Ready to process encrypted file uploads!');
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('🔄 SIGTERM received, shutting down gracefully...');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('🔄 SIGINT received, shutting down gracefully...');
    process.exit(0);
});

/**
 * Aspose Cloud OCR endpoint
 * Accepts a single file upload (multipart/form-data) and optional `language` field.
 * This endpoint exchanges client credentials for an Aspose access token, uploads the file
 * to the Aspose OCR endpoint and returns the OCR result. Set the following env vars:
 * - ASPOSE_CLIENT_ID
 * - ASPOSE_CLIENT_SECRET
 * - ASPOSE_BASE_URL (optional, defaults to https://api.aspose.cloud)
 */
app.post('/aspose/ocr', upload.single('file'), async (req, res) => {
    // API key protection: optional but recommended. If ASPOSE_SERVER_API_KEY is set, require it as `x-api-key` header.
    const serverApiKey = process.env.ASPOSE_SERVER_API_KEY;
    if (serverApiKey) {
        const provided = req.headers['x-api-key'] || req.headers['X-API-KEY'];
        if (!provided || provided !== serverApiKey) {
            return res.status(401).json({ success: false, error: 'Unauthorized' });
        }
    }

    // Simple in-memory token cache
    if (!global.__ASPOSE_TOKEN_CACHE) global.__ASPOSE_TOKEN_CACHE = {};
    const tokenCache = global.__ASPOSE_TOKEN_CACHE;
    try {
        if (!req.file) return res.status(400).json({ success: false, error: 'No file provided' });

        const { originalname, buffer, mimetype } = req.file;
        const language = req.body.language || 'eng';

        const clientId = process.env.ASPOSE_CLIENT_ID;
        const clientSecret = process.env.ASPOSE_CLIENT_SECRET;
        const baseUrl = process.env.ASPOSE_BASE_URL || 'https://api.aspose.cloud';

        if (!clientId || !clientSecret) {
            return res.status(500).json({ success: false, error: 'Aspose credentials not configured' });
        }

        // Obtain OAuth2 token from Aspose Cloud
        const tokenUrl = `${baseUrl}/connect/token`;
        const tokenParams = new URLSearchParams();
        tokenParams.append('grant_type', 'client_credentials');
        tokenParams.append('client_id', clientId);
        tokenParams.append('client_secret', clientSecret);

        // Check cache
        let accessToken = tokenCache.token;
        const now = Date.now();
        if (!accessToken || !tokenCache.expiry || tokenCache.expiry < now) {
            const tokenResp = await axios.post(tokenUrl, tokenParams.toString(), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            });

            accessToken = tokenResp.data && tokenResp.data.access_token;
            const expiresIn = tokenResp.data && tokenResp.data.expires_in ? parseInt(tokenResp.data.expires_in, 10) : 3600;
            if (accessToken) {
                tokenCache.token = accessToken;
                tokenCache.expiry = now + (expiresIn - 60) * 1000; // refresh 60s before expiry
            }
        }

        if (!accessToken) {
            return res.status(500).json({ success: false, error: 'Failed to get Aspose access token' });
        }

        // First, attempt to use official Aspose SDKs when they are installed.
        // This block tries to require product SDKs and call an `extractText` helper on them if available.
        const ext = (originalname.split('.').pop() || '').toLowerCase();
        const sdkCandidates = {
            ocr: 'aspose-ocr-cloud',
            pdf: 'aspose-pdf-cloud',
            slides: 'aspose-slides-cloud',
            cells: 'aspose-cells-cloud',
            words: 'aspose-words-cloud'
        };

        try {
            // Attempt to use installed Aspose Cloud SDKs (PdfApi, SlidesApi, WordsApi, CellsApi)
            // Constructors typically follow: const api = new <Product>Api(clientId, clientSecret)
            if (['jpg','jpeg','png','gif','bmp','webp'].includes(ext)) {
                // Image OCR: Aspose.OCR SDK is uncommon on npm; keep REST flow for images
            }

            if (ext === 'pdf') {
                try {
                    const PdfApi = require('asposepdfcloud').PdfApi;
                    if (PdfApi) {
                        const pdfApi = new PdfApi(clientId, clientSecret);
                        // Use Storage-agnostic convert to text API: convert PDF to TXT
                        // The SDK provides putConvertDocument or similar; attempt common method names
                        if (typeof pdfApi.putConvertDocument === 'function') {
                            // Build request object according to SDK - send file as map
                            const mapFiles = {};
                            mapFiles[originalname] = buffer;
                            const reqObj = { file: mapFiles, format: 'text' };
                            try {
                                const sdkResp = await pdfApi.putConvertDocument(reqObj);
                                if (sdkResp && sdkResp.body) {
                                    const text = sdkResp.body.toString ? sdkResp.body.toString('utf8') : JSON.stringify(sdkResp.body);
                                    return res.json({ success: true, fileName: originalname, text });
                                }
                            } catch (inner) {
                                // fallthrough to REST
                            }
                        }
                    }
                } catch (e) {
                    // package may not be installed or API signature differs
                }
            }

            if (ext === 'ppt' || ext === 'pptx') {
                try {
                    const SlidesApi = require('asposeslidescloud').SlidesApi;
                    if (SlidesApi) {
                        const slidesApi = new SlidesApi(clientId, clientSecret);
                        // Try to convert presentation to text or extract slides in one go
                        if (typeof slidesApi.getPresentationTextItems === 'function') {
                            try {
                                // Upload file as stream if SDK requires storage; attempt online API if available
                                const sdkResp = await slidesApi.getPresentationTextItemsOnline(buffer);
                                if (sdkResp && sdkResp.body) {
                                    const text = typeof sdkResp.body === 'string' ? sdkResp.body : JSON.stringify(sdkResp.body);
                                    return res.json({ success: true, fileName: originalname, text });
                                }
                            } catch (inner) {}
                        }
                    }
                } catch (e) {}
            }

            if (ext === 'xls' || ext === 'xlsx') {
                try {
                    const CellsApi = require('asposecellscloud').CellsApi;
                    if (CellsApi) {
                        const cellsApi = new CellsApi(clientId, clientSecret);
                        // Try convert workbook to text/csv
                        if (typeof cellsApi.putConvertWorkbook === 'function') {
                            try {
                                const request = { file: {}, format: 'csv' };
                                request.file[originalname] = buffer;
                                const sdkResp = await cellsApi.putConvertWorkbook(request);
                                if (sdkResp && sdkResp.body) {
                                    const text = sdkResp.body.toString ? sdkResp.body.toString('utf8') : JSON.stringify(sdkResp.body);
                                    return res.json({ success: true, fileName: originalname, text });
                                }
                            } catch (inner) {}
                        }
                    }
                } catch (e) {}
            }

            if (ext === 'doc' || ext === 'docx') {
                try {
                    const WordsApi = require('asposewordscloud').WordsApi;
                    if (WordsApi) {
                        const wordsApi = new WordsApi(clientId, clientSecret);
                        // Try online conversion to text if available
                        if (typeof wordsApi.convertDocument === 'function' || typeof wordsApi.convertDocumentOnline === 'function') {
                            try {
                                const convertFn = wordsApi.convertDocumentOnline || wordsApi.convertDocument;
                                const req = { file: buffer, format: 'txt' };
                                const sdkResp = await convertFn.call(wordsApi, req);
                                if (sdkResp && sdkResp.body) {
                                    const text = sdkResp.body.toString ? sdkResp.body.toString('utf8') : JSON.stringify(sdkResp.body);
                                    return res.json({ success: true, fileName: originalname, text });
                                }
                            } catch (inner) {}
                        }
                    }
                } catch (e) {}
            }
        } catch (sdkErr) {
            console.warn('Aspose SDK attempt failed, falling back to REST approach:', sdkErr && sdkErr.message ? sdkErr.message : sdkErr);
        }

        // Fallback to generic REST OCR call (previous implementation)
        const form = new FormData();
        form.append('file', buffer, { filename: originalname, contentType: mimetype });
        form.append('language', language);

        // NOTE: Aspose Cloud has product-specific endpoints and versions. The path used here is generic
        // and may need to be adjusted depending on the Aspose product version you are using.
        const ocrEndpoint = `${baseUrl}/ocr/recognize`;

        const ocrResp = await axios.post(ocrEndpoint, form, {
            headers: {
                Authorization: `Bearer ${accessToken}`,
                ...form.getHeaders()
            },
            maxContentLength: Infinity,
            maxBodyLength: Infinity
        });

        // Parse response - exact shape depends on Aspose API version. Try common fields first.
        let resultText = '';
        if (ocrResp.data) {
            if (typeof ocrResp.data === 'string') {
                resultText = ocrResp.data;
            } else if (ocrResp.data.text) {
                resultText = ocrResp.data.text;
            } else if (ocrResp.data.recognition && ocrResp.data.recognition.text) {
                resultText = ocrResp.data.recognition.text;
            } else {
                // Fallback: stringify full payload
                resultText = JSON.stringify(ocrResp.data);
            }
        }

        return res.json({ success: true, fileName: originalname, text: resultText, raw: ocrResp.data });

    } catch (error) {
        console.error('Aspose OCR error:', error && error.response ? error.response.data || error.response.statusText : error.message);
        const message = error && error.response && error.response.data ? JSON.stringify(error.response.data) : (error.message || 'Unknown error');
        return res.status(500).json({ success: false, error: message });
    }
});
