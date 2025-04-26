const crypto = require('crypto');

function hashPassword(password) {
// generating a random salt 
    const salt = crypto.randomBytes(16).toString('hex');

    // Hash the password using PBKDF2 (iterations: 100,000, key length: 64 bytes, hash function: sha512)
    const hashedPassword = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');

    // Return salt:hash
    return `${salt}:${hashedPassword}`;
}

// Function to verify a password against a stored hash
function verifyPassword(password, storedHash) {
    // Extract the salt and stored hash from the storedHash string
    const [salt, storedPasswordHash] = storedHash.split(':');

    const hashedPassword = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');

    return storedPasswordHash === hashedPassword;
}

module.exports = { hashPassword, verifyPassword };
