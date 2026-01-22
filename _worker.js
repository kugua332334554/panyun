const CONFIG = {
    BOT_TOKEN: '',  
    CHANNEL_ID: '', 
    ENCRYPTION_KEY: '' 
};

// 加密函数
async function encrypt(text, key) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    
    // 生成随机iv
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    // 导入密钥
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        encoder.encode(key.padEnd(32, '0').slice(0, 32)),
        { name: 'AES-GCM' },
        false,
        ['encrypt']
    );
    
    // 加密数据
    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        cryptoKey,
        data
    );
    
    // base64
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);
    
    return btoa(String.fromCharCode(...combined))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

// aes解密
async function decrypt(encryptedBase64, key) {
    try {
        const encoder = new TextEncoder();
        
        // 解码base64
        const base64 = encryptedBase64
            .replace(/-/g, '+')
            .replace(/_/g, '/');
        const padding = '='.repeat((4 - base64.length % 4) % 4);
        const combinedStr = atob(base64 + padding);
        const combined = Uint8Array.from(combinedStr, c => c.charCodeAt(0));
        
        // 提取iv
        const iv = combined.slice(0, 12);
        const encrypted = combined.slice(12);
        
        // 导入密钥
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            encoder.encode(key.padEnd(32, '0').slice(0, 32)),
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );
        
        // 解密数据
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            cryptoKey,
            encrypted
        );
        
        return new TextDecoder().decode(decrypted);
    } catch (error) {
        console.error('Decryption error:', error);
        throw new Error('Invalid encryption key or data');
    }
}

// sendtg
async function sendToTelegram(fileBuffer, fileName) {
    try {
        console.log('Sending file to Telegram:', fileName);
        
        const telegramFileName = fileName + '.panyun';
        
        // 创建fd
        const formData = new FormData();
        const blob = new Blob([fileBuffer], { type: 'application/octet-stream' });
        formData.append('document', blob, encodeURIComponent(telegramFileName));
        formData.append('chat_id', CONFIG.CHANNEL_ID);
        
        console.log('Telegram API URL:', `https://api.telegram.org/bot${CONFIG.BOT_TOKEN}/sendDocument`);
        console.log('Telegram filename:', telegramFileName);
        
        const response = await fetch(`https://api.telegram.org/bot${CONFIG.BOT_TOKEN}/sendDocument`, {
            method: 'POST',
            body: formData
        });
        
        const responseText = await response.text();
        console.log('Telegram response:', responseText);
        
        let result;
        try {
            result = JSON.parse(responseText);
        } catch (e) {
            throw new Error(`Invalid JSON response from Telegram: ${responseText}`);
        }
        
        if (!result.ok) {
            throw new Error(`API error: ${result.description || 'Unknown error'}`);
        }
        
        // 从响应中获取file_id和原始文件名
        const fileId = result.result.document?.file_id;
        
        // Telegram 返回的文件名会包含我们添加的 .panyun 后缀
        const telegramResponseFileName = result.result.document?.file_name || telegramFileName;
        
        if (!fileId) {
            throw new Error('No file_id in Telegram response');
        }
        
        console.log('Got file_id:', fileId, 'telegramResponseFileName:', telegramResponseFileName);
        
        return {
            fileId: fileId,
            originalFileName: fileName, // 返回原始文件名（不含 .panyun）
            telegramFileName: telegramResponseFileName // 也返回 Telegram 存储的文件名
        };
        
    } catch (error) {
        console.error('Telegram upload error:', error);
        throw error;
    }
}

// gettg
async function getFileFromTelegram(fileId) {
    try {
        console.log('Getting file info from Telegram for file_id:', fileId);
        
        const response = await fetch(`https://api.telegram.org/bot${CONFIG.BOT_TOKEN}/getFile?file_id=${encodeURIComponent(fileId)}`);
        
        if (!response.ok) {
            throw new Error(`Failed to get file info: ${response.status}`);
        }
        
        const result = await response.json();
        console.log('Telegram getFile response:', JSON.stringify(result));
        
        if (!result.ok) {
            throw new Error(`Telegram error: ${result.description || 'Unknown error'}`);
        }
        
        if (!result.result || !result.result.file_path) {
            throw new Error('No file_path in Telegram response');
        }
        
        // 构建文件下载URL
        const filePath = result.result.file_path;
        const downloadUrl = `https://api.telegram.org/file/bot${CONFIG.BOT_TOKEN}/${filePath}`;
        
        console.log('File download URL:', downloadUrl);
        return downloadUrl;
        
    } catch (error) {
        console.error('Telegram getFile error:', error);
        throw error;
    }
}

// 转义
function encodeFileName(fileName) {
    const safeName = fileName.replace(/[^\w\u4e00-\u9fa5\-\.]/g, '_');
    
    return encodeURIComponent(safeName)
        .replace(/'/g, '%27')
        .replace(/\(/g, '%28')
        .replace(/\)/g, '%29')
        .replace(/\*/g, '%2A');
}

// 下载文件
async function proxyDownload(fileUrl, fileName) {
    try {
        console.log('Proxying download from:', fileUrl);
        console.log('Original filename:', fileName);
        
        const cleanFileName = fileName.replace(/\.panyun$/i, '');
        console.log('Cleaned filename:', cleanFileName);
        
        const response = await fetch(fileUrl);
        
        if (!response.ok) {
            throw new Error(`Failed to download file: ${response.status} ${response.statusText}`);
        }
        
        // 获取原始响应的内容类型
        const contentType = response.headers.get('content-type') || 'application/octet-stream';
        
        // 编码文件名
        const encodedFileName = encodeFileName(cleanFileName);
        
        // 创建响应头
        const headers = new Headers();
        
        // 设置ct头部
        const contentDisposition = `attachment; filename="${encodedFileName}"; filename*=UTF-8''${encodedFileName}`;
        headers.set('Content-Disposition', contentDisposition);
        
        // 设置ct
        headers.set('Content-Type', contentType);
        
        // 复制原始响应的其他头部
        for (const [key, value] of response.headers.entries()) {
            if (key.toLowerCase() !== 'content-disposition') {
                headers.set(key, value);
            }
        }
        
        // 添加CORS头部
        headers.set('Access-Control-Allow-Origin', '*');
        headers.set('Access-Control-Expose-Headers', '*');
        
        console.log('Download headers:', Object.fromEntries(headers.entries()));
        
        // 创建新的响应
        return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: headers
        });
        
    } catch (error) {
        console.error('Proxy download error:', error);
        throw error;
    }
}
// 处理上传请求
async function handleUpload(request) {
    try {
        console.log('Handling upload request');
        
        // 检查请求方法
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({
                success: false,
                error: 'Method not allowed'
            }), {
                status: 405,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                }
            });
        }
        
        // 获取表单数据
        const formData = await request.formData();
        const file = formData.get('file');
        
        if (!file) {
            return new Response(JSON.stringify({
                success: false,
                error: 'No file provided'
            }), {
                status: 400,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                }
            });
        }
        
        // 检查文件大小
        if (file.size > 20 * 1024 * 1024) {
            return new Response(JSON.stringify({
                success: false,
                error: 'File too large (max 20MB)'
            }), {
                status: 413,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                }
            });
        }
        
        console.log('Processing file:', file.name, 'Size:', file.size);
        
        // 读取文件内容
        const arrayBuffer = await file.arrayBuffer();
        const fileBuffer = new Uint8Array(arrayBuffer);
        
        // 发送到tg
        const { fileId, originalFileName } = await sendToTelegram(fileBuffer, file.name);
        
        // 加密数据
        const dataToEncrypt = JSON.stringify({
            f: fileId,
            n: originalFileName
        });
        
        const encryptedId = await encrypt(dataToEncrypt, CONFIG.ENCRYPTION_KEY);
        const downloadId = `dl_${encryptedId}`;
        
        // 构建响应
        const response = {
            success: true,
            download_id: downloadId,
            original_name: originalFileName,
            file_size: file.size,
            download_url: `${new URL(request.url).origin}/d/${downloadId}`,
            timestamp: new Date().toISOString()
        };
        
        console.log('Upload successful, response:', response);
        
        return new Response(JSON.stringify(response, null, 2), {
            status: 200,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
        
    } catch (error) {
        console.error('Upload handler error:', error);
        
        return new Response(JSON.stringify({
            success: false,
            error: error.message || 'Internal server error'
        }), {
            status: 500,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }
}

// 处理下载请求
async function handleDownload(request, pathname) {
    try {
        console.log('Handling download request:', pathname);
        
        // 从路径中提取下载ID
        const match = pathname.match(/^\/d\/(dl_[A-Za-z0-9_-]+)$/);
        if (!match) {
            return new Response(JSON.stringify({
                error: 'Invalid download ID format. Expected format: /d/dl_xxx'
            }), {
                status: 400,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                }
            });
        }
        
        const downloadId = match[1];
        const encryptedId = downloadId.substring(3); 
        
        console.log('Download ID:', downloadId);
        console.log('Encrypted ID:', encryptedId);
        
        // 解密获取数据
        const decryptedData = await decrypt(encryptedId, CONFIG.ENCRYPTION_KEY);
        console.log('Decrypted data:', decryptedData);
        
        let fileId, originalFileName;
        try {
            const data = JSON.parse(decryptedData);
            fileId = data.f;
            originalFileName = data.n || 'download';
        } catch (e) {
            fileId = decryptedData;
            originalFileName = 'download';
        }
        
        console.log('Decrypted file_id:', fileId);
        console.log('Original filename:', originalFileName);
        
        // 获取tg
        const fileUrl = await getFileFromTelegram(fileId);
        
        // 代理下载文件并传递原始文件名
        return await proxyDownload(fileUrl, originalFileName);
        
    } catch (error) {
        console.error('Download handler error:', error);
        
        let status = 500;
        let errorMessage = 'Internal server error';
        
        if (error.message.includes('Invalid encryption') || error.message.includes('Invalid download ID')) {
            status = 400;
            errorMessage = 'Invalid or expired download link';
        } else if (error.message.includes('No file_path') || error.message.includes('not found')) {
            status = 404;
            errorMessage = 'File not found or link expired';
        }
        
        return new Response(JSON.stringify({
            error: errorMessage,
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        }), {
            status: status,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }
}

// 主处理函数
export default {
    async fetch(request, env, ctx) {
        try {
            // 从环境变量加载配置
            CONFIG.BOT_TOKEN = env.TELEGRAM_BOT_TOKEN || CONFIG.BOT_TOKEN;
            CONFIG.CHANNEL_ID = env.TELEGRAM_CHANNEL_ID || CONFIG.CHANNEL_ID;
            CONFIG.ENCRYPTION_KEY = env.ENCRYPTION_KEY || CONFIG.ENCRYPTION_KEY;
            
            // 验证配置
            if (!CONFIG.BOT_TOKEN || !CONFIG.CHANNEL_ID || !CONFIG.ENCRYPTION_KEY) {
                throw new Error('Missing required environment variables');
            }
            
            const url = new URL(request.url);
            const pathname = url.pathname;
            
            console.log('Request:', request.method, pathname);
            
            // 处理ops请求
            if (request.method === 'OPTIONS') {
                return new Response(null, {
                    headers: {
                        'Access-Control-Allow-Origin': '*',
                        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                        'Access-Control-Allow-Headers': 'Content-Type',
                        'Access-Control-Max-Age': '86400'
                    }
                });
            }
            
            // 路由
            if (pathname === '/api/upload') {
                return handleUpload(request);
            }
            
            // 下载路由
            if (pathname.startsWith('/d/')) {
                return handleDownload(request, pathname);
            }
            
            // 文件路由
            if (env.ASSETS) {
                return env.ASSETS.fetch(request);
            }
            
            // 如果没有assets，back404
            return new Response('Not found', {
                status: 404,
                headers: {
                    'Content-Type': 'text/plain',
                    'Access-Control-Allow-Origin': '*'
                }
            });
            
        } catch (error) {
            console.error('Global handler error:', error);
            
            return new Response(JSON.stringify({
                error: 'Internal server error',
                message: process.env.NODE_ENV === 'development' ? error.message : undefined
            }), {
                status: 500,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                }
            });
        }
    }
};
