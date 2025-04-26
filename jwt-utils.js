const crypto = require('crypto');

// Function to Base64 URL encode
function base64urlEncode(str) {
    return Buffer.from(str)
        .toString('base64') // base64 encoding
        .replace(/\+/g, '-') 
        .replace(/\//g, '_') 
        .replace(/=+$/, ''); 
}

// Function to Base64 URL decode 
function base64urlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    const padding = str.length % 4 === 0 ? '' : '='.repeat(4 - str.length % 4);
    return Buffer.from(str + padding, 'base64').toString();
}

// Function to sign JWT 
function signJWT(payload, secret, expiresInSeconds = 3600) {

    const header = {
        alg: 'HS256', // Hashing algorithm
        typ: 'JWT'   
    };

    // Add expiration time to payload (exp is in UNIX timestamp)
    const exp = Math.floor(Date.now() / 1000) + expiresInSeconds; // Expiration time in seconds
    payload.exp = exp;

    const encodedHeader = base64urlEncode(JSON.stringify(header));
    const encodedPayload = base64urlEncode(JSON.stringify(payload));

    const message = `${encodedHeader}.${encodedPayload}`;

    // Sign the message 
    const signature = crypto
        .createHmac('sha256', secret) // HMAC with SHA256 and the provided secret
        .update(message)
        .digest('hex');

    // Return the complete JWT
    return `${message}.${base64urlEncode(signature)}`;
}

// Function to verify JWT
function verifyJWT(token, secret) {
    // Split the token into header, payload, and signature
    const [encodedHeader, encodedPayload, encodedSignature] = token.split('.');

    // Rebuild the message using header and payload
    const message = `${encodedHeader}.${encodedPayload}`;

    const expectedSignature = base64urlDecode(encodedSignature);
    const actualSignature = crypto
        .createHmac('sha256', secret) // HMAC with SHA256 and the provided secret
        .update(message)
        .digest();

    // Use timing-safe comparison to avoid timing attacks
    if (!crypto.timingSafeEqual(expectedSignature, actualSignature)) {
        throw new Error('Invalid signature');
    }

    const decodedPayload = JSON.parse(base64urlDecode(encodedPayload));

    // If the token is expired, throw an error
    if (decodedPayload.exp < Math.floor(Date.now() / 1000)) {
        throw new Error('Token is expired');
    }

    // Return the decoded payload if the token is valid and not expired
    return decodedPayload;
}

module.exports = { signJWT, verifyJWT };
