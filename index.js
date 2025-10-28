/**
 * Azure Blob Storage Upload Server
 * This server handles file uploads to Azure Blob Storage with proper authentication
 * Supports both regular uploads and chunked uploads for large files (up to 10GB+)
 */

const http = require('http');
const { BlobServiceClient } = require('@azure/storage-blob');
const formidable = require('formidable').formidable;
const fs = require('fs');

// Azure Configuration
const CONNECTION_STRING = process.env.CONNECTION_STRING;
const CONTAINER_NAME = process.env.CONTAINER_NAME;

// Create blob service client
const blobServiceClient = BlobServiceClient.fromConnectionString(CONNECTION_STRING);
const containerClient = blobServiceClient.getContainerClient(CONTAINER_NAME);

// Helper function to determine folder based on file type
function getFolderByFileType(fileName, contentType) {
    const extension = fileName.toLowerCase().split('.').pop() || '';

    // Images
    if (contentType.startsWith('image/') ||
        ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp', 'ico'].includes(extension)) {
        return 'images';
    }

    // Videos
    if (contentType.startsWith('video/') ||
        ['mp4', 'avi', 'mov', 'wmv', 'flv', 'mkv', 'webm', 'm4v'].includes(extension)) {
        return 'videos';
    }

    // Documents
    if (['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'csv', 'rtf'].includes(extension)) {
        return 'documents';
    }

    // Audio
    if (contentType.startsWith('audio/') ||
        ['mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a', 'wma'].includes(extension)) {
        return 'audio';
    }

    // Default to 'other' folder
    return 'other';
}

// Create HTTP server
const server = http.createServer(async (req, res) => {
    // Enable CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    // Handle preflight request
    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    // Handle chunked upload endpoint
    if (req.method === 'POST' && req.url === '/upload-chunk') {
        const form = formidable({
            maxFileSize: 50 * 1024 * 1024, // 50MB per chunk max
            keepExtensions: true,
        });

        form.parse(req, async (err, fields, files) => {
            if (err) {
                console.error('❌ Form parse error:', err);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: err.message }));
                return;
            }

            try {
                const fileName = Array.isArray(fields.fileName) ? fields.fileName[0] : fields.fileName;
                const blockId = Array.isArray(fields.blockId) ? fields.blockId[0] : fields.blockId;
                const chunkIndex = Array.isArray(fields.chunkIndex) ? fields.chunkIndex[0] : fields.chunkIndex;
                const chunkFile = files.chunk;

                // Get the uploaded chunk file
                const chunk = Array.isArray(chunkFile) ? chunkFile[0] : chunkFile;

                if (!chunk || !chunk.filepath) {
                    throw new Error('No chunk file received');
                }

                console.log(`📦 Uploading chunk ${chunkIndex} for ${fileName}`, {
                    blockId,
                    size: chunk.size,
                });

                // Determine folder based on file type
                const folder = getFolderByFileType(fileName, chunk.mimetype || 'application/octet-stream');
                const blobName = `${folder}/${fileName}`;

                // Get block blob client
                const blockBlobClient = containerClient.getBlockBlobClient(blobName);

                // Read chunk data
                const chunkData = fs.readFileSync(chunk.filepath);

                // Upload chunk as block
                await blockBlobClient.stageBlock(blockId, chunkData, chunkData.length);

                console.log(`✅ Chunk ${chunkIndex} staged successfully`);

                // Clean up temp file
                fs.unlinkSync(chunk.filepath);

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    success: true,
                    blockId,
                    chunkIndex,
                }));

            } catch (error) {
                console.error('❌ Chunk upload error:', error);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    success: false,
                    error: error.message
                }));
            }
        });
        return;
    }

    // Handle commit blocks endpoint
    if (req.method === 'POST' && req.url === '/commit-blocks') {
        let body = '';

        req.on('data', chunk => {
            body += chunk.toString();
        });

        req.on('end', async () => {
            try {
                const { fileName, blockIds, contentType, metadata } = JSON.parse(body);

                console.log('🔄 Committing blocks for:', {
                    fileName,
                    totalBlocks: blockIds.length,
                    contentType,
                });

                // Determine folder based on file type
                const folder = getFolderByFileType(fileName, contentType);
                const blobName = `${folder}/${fileName}`;

                // Get block blob client
                const blockBlobClient = containerClient.getBlockBlobClient(blobName);

                // Commit block list to create the final blob
                await blockBlobClient.commitBlockList(blockIds, {
                    blobHTTPHeaders: {
                        blobContentType: contentType,
                    },
                    metadata: metadata || {},
                });

                const blobUrl = blockBlobClient.url;

                console.log('✅ Blocks committed successfully:', {
                    blobUrl,
                    folder,
                    fileName,
                    totalBlocks: blockIds.length,
                });

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    success: true,
                    url: blobUrl,
                    folder,
                    fileName,
                }));

            } catch (error) {
                console.error('❌ Commit blocks error:', error);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    success: false,
                    error: error.message
                }));
            }
        });
        return;
    }

    // Only handle POST requests to /upload (legacy endpoint for small files)
    if (req.method === 'POST' && req.url === '/upload') {
        let body = '';

        req.on('data', chunk => {
            body += chunk.toString();
        });

        req.on('end', async () => {
            try {
                const { fileName, content, contentType, metadata } = JSON.parse(body);

                console.log('📤 Received upload request:', {
                    fileName,
                    contentType,
                    contentLength: content.length,
                    metadata
                });

                // Determine folder based on file type
                const folder = getFolderByFileType(fileName, contentType);
                const blobName = `${folder}/${fileName}`;

                console.log('📁 Uploading to folder:', folder);

                // Get block blob client
                const blockBlobClient = containerClient.getBlockBlobClient(blobName);

                // Convert base64 to buffer
                let buffer;
                if (content.startsWith('data:')) {
                    const base64Data = content.split(',')[1];
                    buffer = Buffer.from(base64Data, 'base64');
                } else {
                    buffer = Buffer.from(content, 'base64');
                }

                // Upload to Azure
                const uploadResponse = await blockBlobClient.upload(buffer, buffer.length, {
                    blobHTTPHeaders: {
                        blobContentType: contentType,
                    },
                    metadata: metadata || {},
                });

                const blobUrl = blockBlobClient.url;

                console.log('✅ Upload successful:', {
                    blobUrl,
                    requestId: uploadResponse.requestId,
                    folder,
                    fileName
                });

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    success: true,
                    url: blobUrl,
                    folder,
                    fileName,
                    requestId: uploadResponse.requestId
                }));

            } catch (error) {
                console.error('❌ Upload error:', error);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    success: false,
                    error: error.message
                }));
            }
        });
    } else {
        res.writeHead(404);
        res.end('Not Found');
    }
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
    console.log(`🚀 Azure Upload Server running on http://localhost:${PORT}`);
    console.log(`📦 Container: ${CONTAINER_NAME}`);
    console.log(`☁️  Storage Account: ${process.env.ACCOUNT_NAME || ''}`);
    console.log(`\n✅ Ready to receive upload requests at http://localhost:${PORT}/upload`);
});
