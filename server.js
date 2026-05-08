const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');

const app = express();
app.use(cors());
app.use(express.json());

let db;
(async () => {
    db = await open({
        filename: './rovii.db',
        driver: sqlite3.Database
    });
    await db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            username TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `);
    console.log('✅ Rovii database ready');
})();

app.get('/', (req, res) => {
    res.json({ message: 'Rovii Backend is running! ❤️', status: 'ok' });
});

app.post('/api/register', async (req, res) => {
    let { username, password } = req.body;
    if (!username || username.length < 3) return res.json({ success: false, message: 'Username min 3 chars' });
    if (!password || password.length < 4) return res.json({ success: false, message: 'Password min 4 chars' });
    
    let existing = await db.get('SELECT username FROM users WHERE username = ?', [username]);
    if (existing) return res.json({ success: false, message: 'Username taken' });
    
    let hashed = await bcrypt.hash(password, 10);
    await db.run('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, hashed]);
    res.json({ success: true });
});

app.post('/api/login', async (req, res) => {
    let { username, password } = req.body;
    let user = await db.get('SELECT username, password_hash FROM users WHERE username = ?', [username]);
    if (!user) return res.json({ success: false, message: 'User not found' });
    
    let match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.json({ success: false, message: 'Wrong password' });
    
    let sessionId = crypto.randomBytes(32).toString('hex');
    await db.run('INSERT INTO sessions (session_id, username) VALUES (?, ?)', [sessionId, username]);
    res.json({ success: true, sessionId, username });
});

app.post('/api/verify', async (req, res) => {
    let { sessionId } = req.body;
    let sess = await db.get('SELECT username FROM sessions WHERE session_id = ?', [sessionId]);
    if (sess) res.json({ valid: true, username: sess.username });
    else res.json({ valid: false });
});

app.get('/user-exists', async (req, res) => {
    let { username } = req.query;
    let user = await db.get('SELECT username FROM users WHERE username = ?', [username]);
    res.json({ exists: !!user });
});

app.post('/api/logout', async (req, res) => {
    let { sessionId } = req.body;
    await db.run('DELETE FROM sessions WHERE session_id = ?', [sessionId]);
    res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Rovii server on port ${PORT}`));
