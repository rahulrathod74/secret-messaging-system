const express = require('express');
const crypto = require('crypto'); // Built-in crypto module
const bcrypt = require('bcrypt'); // External library
const CryptoJS = require('crypto-js'); // External library

const app = express();
app.use(express.json()); // Built-in JSON parser

// Storage for encrypted and hashed data
let storage = [];

// Encryption and decryption keys
const CRYPTO_SECRET = 'my-secret-key';
const CRYPTOJS_SECRET = 'my-external-secret';

// Routes

// 1. Encryption and Decryption using Crypto Module
app.post('/encrypt/crypto', (req, res) => {
    const { message } = req.body;

    const cipher = crypto.createCipher('aes-256-cbc', CRYPTO_SECRET);
    let encrypted = cipher.update(message, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    res.json({ encrypted });
});

app.post('/decrypt/crypto', (req, res) => {
    const { encryptedMessage } = req.body;

    const decipher = crypto.createDecipher('aes-256-cbc', CRYPTO_SECRET);
    let decrypted = decipher.update(encryptedMessage, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    res.json({ decrypted });
});

// 2. Encryption and Decryption using External Module
app.post('/encrypt/external', (req, res) => {
    const { message } = req.body;

    const encrypted = CryptoJS.AES.encrypt(message, CRYPTOJS_SECRET).toString();
    res.json({ encrypted });
});

app.post('/decrypt/external', (req, res) => {
    const { encryptedMessage } = req.body;

    const bytes = CryptoJS.AES.decrypt(encryptedMessage, CRYPTOJS_SECRET);
    const decrypted = bytes.toString(CryptoJS.enc.Utf8);

    res.json({ decrypted });
});

// 3. Hashing and Verifying with Crypto Module
app.post('/hash/crypto', (req, res) => {
    const { message } = req.body;

    const hashed = crypto.createHash('sha256').update(message).digest('hex');
    res.json({ hashed });
});

app.post('/verify/crypto', (req, res) => {
    const { message, hashedMessage } = req.body;

    const hashed = crypto.createHash('sha256').update(message).digest('hex');
    const isMatch = hashed === hashedMessage;

    res.json({ isMatch });
});

// 4. Hashing and Verifying with External Module
app.post('/hash/external', async (req, res) => {
    const { message } = req.body;

    const saltRounds = 10;
    const hashed = await bcrypt.hash(message, saltRounds);
    res.json({ hashed });
});

app.post('/verify/external', async (req, res) => {
    const { message, hashedMessage } = req.body;

    const isMatch = await bcrypt.compare(message, hashedMessage);
    res.json({ isMatch });
});

// 5. Storing Encrypted and Hashed Data
app.post('/store', (req, res) => {
    const { message, encrypted, hashed } = req.body;

    storage.push({ message, encrypted, hashed });
    res.json({ message: 'Data stored successfully', storage });
});

app.get('/storage', (req, res) => {
    res.json(storage);
});

// Start server
const PORT = 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
