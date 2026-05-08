const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { Server } = require('socket.io');
const http = require('http');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

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
        CREATE TABLE IF NOT EXISTS groups (
            groupId TEXT PRIMARY KEY,
            admin TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS group_members (
            groupId TEXT,
            username TEXT,
            joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            groupId TEXT,
            username TEXT,
            text TEXT,
            time TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `);
    console.log('✅ Database ready');
})();

app.get('/', (req, res) => {
    res.json({ message: 'Rovii Backend is running!', status: 'ok' });
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

// Username update endpoint
app.post('/api/update-username', async (req, res) => {
    let { oldUsername, newUsername, password } = req.body;
    if (!oldUsername || !newUsername || newUsername.length < 3) {
        return res.json({ success: false, message: 'Invalid username' });
    }
    let user = await db.get('SELECT password_hash FROM users WHERE username = ?', [oldUsername]);
    if (!user) return res.json({ success: false, message: 'User not found' });
    let match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.json({ success: false, message: 'Wrong password' });
    let existing = await db.get('SELECT username FROM users WHERE username = ?', [newUsername]);
    if (existing) return res.json({ success: false, message: 'Username already taken' });
    
    await db.run('UPDATE users SET username = ? WHERE username = ?', [newUsername, oldUsername]);
    await db.run('UPDATE sessions SET username = ? WHERE username = ?', [newUsername, oldUsername]);
    await db.run('UPDATE group_members SET username = ? WHERE username = ?', [newUsername, oldUsername]);
    await db.run('UPDATE messages SET username = ? WHERE username = ?', [newUsername, oldUsername]);
    await db.run('UPDATE groups SET admin = ? WHERE admin = ?', [newUsername, oldUsername]);
    
    res.json({ success: true, newUsername });
});

// Socket.io events
io.on('connection', (socket) => {
    let currentUser = null;
    let currentGroup = null;

    socket.on('create-group', async ({ userId }) => {
        currentUser = userId;
        let groupId = crypto.randomBytes(4).toString('hex');
        await db.run('INSERT INTO groups (groupId, admin) VALUES (?, ?)', [groupId, userId]);
        await db.run('INSERT INTO group_members (groupId, username) VALUES (?, ?)', [groupId, userId]);
        socket.join(groupId);
        currentGroup = groupId;
        socket.emit('group-created', groupId);
        
        let msgs = await db.all('SELECT username, text, time FROM messages WHERE groupId = ? ORDER BY id', [groupId]);
        socket.emit('old-messages', msgs || []);
        
        const roomSockets = await io.in(groupId).fetchSockets();
        const users = roomSockets.map(s => s.currentUser).filter(Boolean);
        io.to(groupId).emit('online-users', users);
    });

    socket.on('join-group', async ({ groupId, userId }) => {
        let group = await db.get('SELECT groupId FROM groups WHERE groupId = ?', [groupId]);
        if (!group) {
            socket.emit('error', 'Group not found');
            return;
        }
        currentUser = userId;
        await db.run('INSERT OR IGNORE INTO group_members (groupId, username) VALUES (?, ?)', [groupId, userId]);
        socket.join(groupId);
        currentGroup = groupId;
        socket.emit('joined-group', groupId);
        
        let msgs = await db.all('SELECT username, text, time FROM messages WHERE groupId = ? ORDER BY id', [groupId]);
        socket.emit('old-messages', msgs || []);
        
        const roomSockets = await io.in(groupId).fetchSockets();
        const users = roomSockets.map(s => s.currentUser).filter(Boolean);
        io.to(groupId).emit('online-users', users);
    });

    socket.on('rejoin-group', async ({ groupId, userId }) => {
        currentUser = userId;
        currentGroup = groupId;
        socket.join(groupId);
        let msgs = await db.all('SELECT username, text, time FROM messages WHERE groupId = ? ORDER BY id', [groupId]);
        socket.emit('old-messages', msgs || []);
        const roomSockets = await io.in(groupId).fetchSockets();
        const users = roomSockets.map(s => s.currentUser).filter(Boolean);
        io.to(groupId).emit('online-users', users);
    });

    socket.on('send-message', async ({ groupId, msg }) => {
        await db.run('INSERT INTO messages (groupId, username, text, time) VALUES (?, ?, ?, ?)', 
            [groupId, msg.user, msg.text, msg.time]);
        io.to(groupId).emit('new-message', msg);
    });

    socket.on('play-video', ({ groupId, videoId }) => {
        io.to(groupId).emit('sync-video', { videoId });
    });

    socket.on('disconnect', async () => {
        if (currentGroup && currentUser) {
            const roomSockets = await io.in(currentGroup).fetchSockets();
            const users = roomSockets.map(s => s.currentUser).filter(Boolean);
            io.to(currentGroup).emit('online-users', users);
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`🚀 Rovii server running on port ${PORT}`));
