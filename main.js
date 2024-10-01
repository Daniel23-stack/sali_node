// main.js
const axios = require('axios');
const fs = require('fs');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const mongoose = require('mongoose');
const WebSocket = require('ws');
const createCsvWriter = require('csv-writer').createObjectCsvWriter;

const loginUrl = 'https://challenge.sedilink.co.za:12022';
const postUrl = 'https://challenge.sedilink.co.za:12022';

// ---- Utility Functions ----

// Encrypt data using AES-256-CBC
function encryptData(data) {
    const key = crypto.randomBytes(32); // 256 bits
    const iv = crypto.randomBytes(16); // 128 bits
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return {
        iv: iv.toString('hex'),
        encryptedData: encrypted,
        key: key.toString('hex'),
    };
}

// Decrypt data using AES-256-CBC
function decryptData(encryptedData) {
    const { iv, encryptedData: encData, key } = JSON.parse(encryptedData);
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));
    let decrypted = decipher.update(Buffer.from(encData, 'hex'));
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

// ---- Step 1: Simulate Secure Login ----
async function secureLogin() {
    try {
        const response = await axios.post(
            loginUrl,
            { username: 'testuser', password: 'testpass', action: 'LOGIN' },
            { httpsAgent: new (require('https').Agent)({ rejectUnauthorized: false }) }
        );
        console.log('Logged in successfully:', response.data);
        return response.data.token;
    } catch (error) {
        console.error('Login failed:', error);
        return null;
    }
}

// ---- Step 2: Deduplicate User Data ----
async function handleUserData(token) {
    const rawData = fs.readFileSync('users.json', 'utf8');
    const users = JSON.parse(decryptData(rawData));

    // Deduplicate users
    const uniqueUsers = [];
    const userMap = new Map();

    users.forEach((user) => {
        const key = `${user.name}-${user.surname}`;
        if (!userMap.has(key)) {
            user.id = uuidv4(); // Add a unique ID
            userMap.set(key, user);
            uniqueUsers.push(user);
        }
    });

    // Save the unique users to a new file
    fs.writeFileSync('uniqueUsers.json', JSON.stringify(uniqueUsers, null, 2));
    console.log('Created `uniqueUsers.json` successfully.');
}

// ---- Step 3: Simulate Secure Posting ----
async function postUsersData(token) {
    const usersData = JSON.parse(fs.readFileSync('uniqueUsers.json', 'utf8'));

    for (const user of usersData) {
        try {
            await axios.post(
                postUrl,
                { ...user, token: token },
                {
                    headers: { 'Content-Type': 'application/json' },
                    httpsAgent: new (require('https').Agent)({ rejectUnauthorized: false }),
                }
            );
            console.log(`User ${user.name} ${user.surname} posted successfully.`);
        } catch (error) {
            console.error(`Failed to post user ${user.name}:`, error);
        }
    }
}

// ---- Step 4: MongoDB Integration ----
async function queryEngineeringDepartment() {
    await mongoose.connect('mongodb://localhost:27017/engineering', {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    });

    const userSchema = new mongoose.Schema({
        id: String,
        name: String,
        surname: String,
        designation: String,
        department: String,
        supervisor: String,
    });

    const User = mongoose.model('User', userSchema);
    const reportingUsers = await User.find({
        department: 'Engineering',
        supervisor: 'Michael Phalane',
        designation: { $in: ['Mechanic', 'Mechanic Assistant'] },
    });

    console.log(`Total number of users reporting to Michael Phalane: ${reportingUsers.length}`);
    mongoose.disconnect();
}


function connectWebSocket() {
    const ws = new WebSocket('wss://challenge.sedilink.co.za:3006');

    ws.on('open', () => {
        const message = 'Node.js WebSocket Client';
        console.log(`Sending message: ${message}`);
        ws.send(message);
    });

    ws.on('message', (data) => {
        const reversedMessage = data.toString();
        console.log(`Received message: ${reversedMessage}`);
        ws.close();
    });

    ws.on('error', (err) => {
        console.error('WebSocket error:', err);
    });

    ws.on('close', () => {
        console.log('WebSocket connection closed.');
    });
}

// ---- Main Execution ----
async function main() {
    // 1. Secure login to get the session token
    const token = await secureLogin();
    if (!token) return;

    // 2. Handle user data deduplication
    await handleUserData(token);

    // 3. Securely post unique users
    await postUsersData(token);

    // 4. Query MongoDB for specific users
    await queryEngineeringDepartment();

    // 5. Run WebSocket client (Bonus)
    connectWebSocket();
}

main();
