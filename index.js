#!/usr/bin/env node
/**
 * Server Startup Script for NIQ File Services
 * Handles server installation, configuration, and startup
 */

const { spawn, exec } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('🚀 NIQ File Services Server Startup');
console.log('===================================');

// Configuration
const SERVER_PORT = process.env.PORT || 3001;
const SERVER_FILE = 'file-services-server.js';

// Check if server file exists
if (!fs.existsSync(SERVER_FILE)) {
    console.error(`❌ Server file not found: ${SERVER_FILE}`);
    process.exit(1);
}

// Function to install dependencies
function installDependencies() {
    return new Promise((resolve, reject) => {
        console.log('📦 Installing server dependencies...');
        
        const installCmd = 'npm install express multer @azure/storage-blob cors dotenv';
        
        exec(installCmd, (error, stdout, stderr) => {
            if (error) {
                console.error('❌ Failed to install dependencies:', error.message);
                reject(error);
                return;
            }
            
            if (stderr) {
                console.log('⚠️ Install warnings:', stderr);
            }
            
            console.log('✅ Dependencies installed successfully');
            resolve();
        });
    });
}

// Function to check environment variables
function checkEnvironment() {
    console.log('🔍 Checking environment configuration...');
    
    const requiredEnvVars = [
        'CONNECTION_STRING',
        'AZURE_STORAGE_CONNECTION_STRING'
    ];
    
    const missingVars = [];
    
    for (const varName of requiredEnvVars) {
        if (!process.env[varName]) {
            missingVars.push(varName);
        }
    }
    
    if (missingVars.length > 0) {
        console.log('⚠️ Missing environment variables:');
        missingVars.forEach(varName => {
            console.log(`   • ${varName}`);
        });
        console.log('');
        console.log('💡 You can set them in:');
        console.log('   • .env file in the project root');
        console.log('   • System environment variables');
        console.log('   • Command line: SET VARIABLE_NAME=value (Windows)');
        console.log('');
        console.log('🔄 Server will attempt to start anyway...');
    } else {
        console.log('✅ Environment configuration looks good');
    }
}

// Function to start the server
function startServer() {
    return new Promise((resolve, reject) => {
        console.log('🎯 Starting File Services Server...');
        
        const serverProcess = spawn('node', [SERVER_FILE], {
            stdio: 'inherit',
            env: {
                ...process.env,
                PORT: SERVER_PORT
            }
        });
        
        serverProcess.on('error', (error) => {
            console.error('❌ Failed to start server:', error.message);
            reject(error);
        });
        
        serverProcess.on('exit', (code) => {
            if (code !== 0) {
                console.error(`❌ Server exited with code ${code}`);
                reject(new Error(`Server exited with code ${code}`));
            } else {
                console.log('✅ Server shut down gracefully');
                resolve();
            }
        });
        
        // Handle Ctrl+C
        process.on('SIGINT', () => {
            console.log('\n🔄 Shutting down server...');
            serverProcess.kill('SIGINT');
        });
        
        process.on('SIGTERM', () => {
            console.log('\n🔄 Shutting down server...');
            serverProcess.kill('SIGTERM');
        });
    });
}

// Main startup sequence
async function main() {
    try {
        // Check if dependencies are installed
        if (!fs.existsSync('node_modules')) {
            await installDependencies();
        } else {
            console.log('✅ Dependencies already installed');
        }
        
        // Check environment
        checkEnvironment();
        
        // Start server
        console.log('');
        await startServer();
        
    } catch (error) {
        console.error('💥 Startup failed:', error.message);
        process.exit(1);
    }
}

// Handle command line arguments
const args = process.argv.slice(2);

if (args.includes('--install-only')) {
    installDependencies()
        .then(() => {
            console.log('✅ Dependencies installed. Run without --install-only to start server.');
            process.exit(0);
        })
        .catch((error) => {
            console.error('❌ Installation failed:', error.message);
            process.exit(1);
        });
} else {
    main();
}
