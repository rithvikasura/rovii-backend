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
app.use(express.json({ limit: '10mb' }));

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

let db;
(async () => {
    try {
        db = await open({
            filename: './rovii.db',
            driver: sqlite3.Database
        });
        await db.exec(`
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT,
                profile_pic TEXT,
                mother_name TEXT,
                father_name TEXT,
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
                current_video TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS group_members (
                groupId TEXT,
                username TEXT,
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS group_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                groupId TEXT,
                username TEXT,
                text TEXT,
                time TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS private_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_user TEXT,
                to_user TEXT,
                text TEXT,
                time TEXT,
                is_read INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS friends (
                user1 TEXT,
                user2 TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user1, user2)
            );
            CREATE TABLE IF NOT EXISTS friend_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_user TEXT,
                to_user TEXT,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('Database ready');
    } catch(err) {
        console.error('Database error:', err);
    }
})();

function getISTTime() {
    const now = new Date();
    const istOffset = 5.5 * 60 * 60 * 1000;
    const istDate = new Date(now.getTime() + istOffset);
    const hours = istDate.getUTCHours().toString().padStart(2, '0');
    const minutes = istDate.getUTCMinutes().toString().padStart(2, '0');
    const seconds = istDate.getUTCSeconds().toString().padStart(2, '0');
    return `${hours}:${minutes}:${seconds}`;
}

app.get('/', (req, res) => {
    res.json({ message: 'Rovii Backend is running!', status: 'ok' });
});

app.post('/api/register', async (req, res) => {
    try {
        let { username, password, motherName, fatherName } = req.body;
        if (!username || username.length < 3) return res.json({ success: false, message: 'Min 3 chars' });
        if (!password || password.length < 4) return res.json({ success: false, message: 'Min 4 chars' });
        let existing = await db.get('SELECT username FROM users WHERE username = ?', [username]);
        if (existing) return res.json({ success: false, message: 'Username taken' });
        let hashed = await bcrypt.hash(password, 10);
        let motherHash = motherName ? await bcrypt.hash(motherName.toLowerCase(), 10) : null;
        let fatherHash = fatherName ? await bcrypt.hash(fatherName.toLowerCase(), 10) : null;
        await db.run('INSERT INTO users (username, password_hash, mother_name, father_name) VALUES (?, ?, ?, ?)', 
            [username, hashed, motherHash, fatherHash]);
        res.json({ success: true });
    } catch(e) {
        res.json({ success: false, message: e.message });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        let { username, password } = req.body;
        let user = await db.get('SELECT username, password_hash, profile_pic FROM users WHERE username = ?', [username]);
        if (!user) return res.json({ success: false, message: 'User not found' });
        let match = await bcrypt.compare(password, user.password_hash);
        if (!match) return res.json({ success: false, message: 'Wrong password' });
        let sessionId = crypto.randomBytes(32).toString('hex');
        // Delete old sessions for this user
        await db.run('DELETE FROM sessions WHERE username = ?', [username]);
        await db.run('INSERT INTO sessions (session_id, username) VALUES (?, ?)', [sessionId, username]);
        res.json({ success: true, sessionId, username, profilePic: user.profile_pic || null });
    } catch(e) {
        res.json({ success: false, message: e.message });
    }
});

app.post('/api/verify', async (req, res) => {
    try {
        let { sessionId } = req.body;
        let sess = await db.get('SELECT username FROM sessions WHERE session_id = ?', [sessionId]);
        if (sess) {
            let user = await db.get('SELECT profile_pic FROM users WHERE username = ?', [sess.username]);
            res.json({ valid: true, username: sess.username, profilePic: user ? user.profile_pic : null });
        } else res.json({ valid: false });
    } catch(e) {
        res.json({ valid: false });
    }
});

app.post('/api/forgot-password', async (req, res) => {
    try {
        let { username, motherName, fatherName, newPassword } = req.body;
        let user = await db.get('SELECT mother_name, father_name FROM users WHERE username = ?', [username]);
        if (!user) return res.json({ success: false, message: 'User not found' });
        let motherMatch = user.mother_name ? await bcrypt.compare(motherName.toLowerCase(), user.mother_name) : false;
        let fatherMatch = user.father_name ? await bcrypt.compare(fatherName.toLowerCase(), user.father_name) : false;
        if (!motherMatch || !fatherMatch) return res.json({ success: false, message: 'Security answers incorrect' });
        let hashed = await bcrypt.hash(newPassword, 10);
        await db.run('UPDATE users SET password_hash = ? WHERE username = ?', [hashed, username]);
        res.json({ success: true });
    } catch(e) {
        res.json({ success: false, message: e.message });
    }
});

app.get('/user-exists', async (req, res) => {
    try {
        let { username } = req.query;
        let user = await db.get('SELECT username FROM users WHERE username = ?', [username]);
        res.json({ exists: !!user });
    } catch(e) {
        res.json({ exists: false });
    }
});

app.get('/api/get-pic', async (req, res) => {
    try {
        let { username } = req.query;
        let user = await db.get('SELECT profile_pic FROM users WHERE username = ?', [username]);
        res.json({ profilePic: user ? user.profile_pic : null });
    } catch(e) {
        res.json({ profilePic: null });
    }
});

app.post('/api/upload-pic', async (req, res) => {
    try {
        let { username, imageData } = req.body;
        if (!username || !imageData) return res.json({ success: false });
        await db.run('UPDATE users SET profile_pic = ? WHERE username = ?', [imageData, username]);
        res.json({ success: true });
    } catch(e) {
        res.json({ success: false });
    }
});

app.post('/api/update-username', async (req, res) => {
    try {
        let { oldUsername, newUsername, password } = req.body;
        if (!oldUsername || !newUsername || newUsername.length < 3) {
            return res.json({ success: false, message: 'Invalid username' });
        }
        let user = await db.get('SELECT password_hash FROM users WHERE username = ?', [oldUsername]);
        if (!user) return res.json({ success: false, message: 'User not found' });
        let match = await bcrypt.compare(password, user.password_hash);
        if (!match) return res.json({ success: false, message: 'Wrong password' });
        let existing = await db.get('SELECT username FROM users WHERE username = ?', [newUsername]);
        if (existing) return res.json({ success: false, message: 'Username taken' });
        
        let pic = await db.get('SELECT profile_pic FROM users WHERE username = ?', [oldUsername]);
        await db.run('UPDATE users SET username = ?, profile_pic = ? WHERE username = ?', 
            [newUsername, pic ? pic.profile_pic : null, oldUsername]);
        await db.run('UPDATE sessions SET username = ? WHERE username = ?', [newUsername, oldUsername]);
        await db.run('UPDATE group_members SET username = ? WHERE username = ?', [newUsername, oldUsername]);
        await db.run('UPDATE group_messages SET username = ? WHERE username = ?', [newUsername, oldUsername]);
        await db.run('UPDATE groups SET admin = ? WHERE admin = ?', [newUsername, oldUsername]);
        await db.run('UPDATE private_messages SET from_user = ? WHERE from_user = ?', [newUsername, oldUsername]);
        await db.run('UPDATE private_messages SET to_user = ? WHERE to_user = ?', [newUsername, oldUsername]);
        await db.run('UPDATE friends SET user1 = ? WHERE user1 = ?', [newUsername, oldUsername]);
        await db.run('UPDATE friends SET user2 = ? WHERE user2 = ?', [newUsername, oldUsername]);
        await db.run('UPDATE friend_requests SET from_user = ? WHERE from_user = ?', [newUsername, oldUsername]);
        await db.run('UPDATE friend_requests SET to_user = ? WHERE to_user = ?', [newUsername, oldUsername]);
        
        res.json({ success: true, newUsername });
    } catch(e) {
        res.json({ success: false, message: e.message });
    }
});

app.get('/api/private-messages', async (req, res) => {
    try {
        let { user1, user2 } = req.query;
        let msgs = await db.all(
            `SELECT from_user, to_user, text, time FROM private_messages 
             WHERE (from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?)
             ORDER BY created_at`,
            [user1, user2, user2, user1]
        );
        res.json({ messages: msgs });
    } catch(e) {
        res.json({ messages: [] });
    }
});

app.post('/api/send-friend-request', async (req, res) => {
    try {
        let { from, to } = req.body;
        let existingFriend = await db.get('SELECT * FROM friends WHERE (user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?)', 
            [from, to, to, from]);
        if (existingFriend) return res.json({ success: false, message: 'Already friends' });
        let existingReq = await db.get('SELECT * FROM friend_requests WHERE from_user = ? AND to_user = ? AND status = "pending"', [from, to]);
        if (existingReq) return res.json({ success: false, message: 'Request already sent' });
        await db.run('INSERT INTO friend_requests (from_user, to_user) VALUES (?, ?)', [from, to]);
        res.json({ success: true });
    } catch(e) {
        res.json({ success: false, message: e.message });
    }
});

app.get('/api/friend-requests', async (req, res) => {
    try {
        let { username } = req.query;
        let requests = await db.all('SELECT from_user FROM friend_requests WHERE to_user = ? AND status = "pending"', [username]);
        res.json({ requests: requests.map(r => r.from_user) });
    } catch(e) {
        res.json({ requests: [] });
    }
});

app.post('/api/accept-friend', async (req, res) => {
    try {
        let { from, to } = req.body;
        await db.run('UPDATE friend_requests SET status = "accepted" WHERE from_user = ? AND to_user = ?', [from, to]);
        await db.run('INSERT INTO friends (user1, user2) VALUES (?, ?)', [from, to]);
        res.json({ success: true });
    } catch(e) {
        res.json({ success: false });
    }
});

app.post('/api/reject-friend', async (req, res) => {
    try {
        let { from, to } = req.body;
        await db.run('DELETE FROM friend_requests WHERE from_user = ? AND to_user = ?', [from, to]);
        res.json({ success: true });
    } catch(e) {
        res.json({ success: false });
    }
});

app.get('/api/friends', async (req, res) => {
    try {
        let { username } = req.query;
        let friendsList = await db.all(
            `SELECT user1 as friend FROM friends WHERE user2 = ?
             UNION SELECT user2 as friend FROM friends WHERE user1 = ?`,
            [username, username]
        );
        res.json({ friends: friendsList.map(f => f.friend) });
    } catch(e) {
        res.json({ friends: [] });
    }
});

app.post('/api/remove-friend', async (req, res) => {
    try {
        let { user1, user2 } = req.body;
        await db.run('DELETE FROM friends WHERE (user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?)', [user1, user2, user2, user1]);
        res.json({ success: true });
    } catch(e) {
        res.json({ success: false });
    }
});

const onlineUsers = new Map();

io.on('connection', (socket) => {
    let currentUser = null;
    let currentGroup = null;

    socket.on('register-user', ({ username }) => {
        currentUser = username;
        onlineUsers.set(socket.id, username);
        socket.username = username;
        console.log(`${username} connected`);
    });

    socket.on('create-group', async ({ userId }) => {
        try {
            currentUser = userId;
            let groupId = crypto.randomBytes(4).toString('hex');
            await db.run('INSERT INTO groups (groupId, admin) VALUES (?, ?)', [groupId, userId]);
            await db.run('INSERT INTO group_members (groupId, username) VALUES (?, ?)', [groupId, userId]);
            socket.join(groupId);
            currentGroup = groupId;
            socket.emit('group-created', groupId);
            socket.emit('admin-status', true);
            
            let msgs = await db.all('SELECT username, text, time FROM group_messages WHERE groupId = ? ORDER BY id', [groupId]);
            socket.emit('old-messages', msgs || []);
            updateOnlineUsers(groupId);
        } catch(e) {
            console.error(e);
        }
    });

    socket.on('join-group', async ({ groupId, userId }) => {
        try {
            let group = await db.get('SELECT groupId, current_video FROM groups WHERE groupId = ?', [groupId]);
            if (!group) {
                socket.emit('error', 'Group not found');
                return;
            }
            currentUser = userId;
            await db.run('INSERT OR IGNORE INTO group_members (groupId, username) VALUES (?, ?)', [groupId, userId]);
            socket.join(groupId);
            currentGroup = groupId;
            socket.emit('joined-group', groupId);
            
            let isAdmin = false;
            let adminCheck = await db.get('SELECT admin FROM groups WHERE groupId = ? AND admin = ?', [groupId, userId]);
            if(adminCheck) isAdmin = true;
            socket.emit('admin-status', isAdmin);
            
            if (group.current_video) {
                socket.emit('sync-video', { videoId: group.current_video });
            }
            
            let msgs = await db.all('SELECT username, text, time FROM group_messages WHERE groupId = ? ORDER BY id', [groupId]);
            socket.emit('old-messages', msgs || []);
            updateOnlineUsers(groupId);
        } catch(e) {
            console.error(e);
        }
    });

    socket.on('rejoin-group', async ({ groupId, userId }) => {
        try {
            currentUser = userId;
            currentGroup = groupId;
            socket.join(groupId);
            let group = await db.get('SELECT current_video FROM groups WHERE groupId = ?', [groupId]);
            if (group && group.current_video) {
                socket.emit('sync-video', { videoId: group.current_video });
            }
            let msgs = await db.all('SELECT username, text, time FROM group_messages WHERE groupId = ? ORDER BY id', [groupId]);
            socket.emit('old-messages', msgs || []);
            updateOnlineUsers(groupId);
        } catch(e) {
            console.error(e);
        }
    });

    socket.on('send-message', async ({ groupId, msg }) => {
        try {
            const serverTime = getISTTime();
            const messageWithTime = { user: msg.user, text: msg.text, time: serverTime };
            await db.run('INSERT INTO group_messages (groupId, username, text, time) VALUES (?, ?, ?, ?)', 
                [groupId, msg.user, msg.text, serverTime]);
            io.to(groupId).emit('new-message', messageWithTime);
        } catch(e) {
            console.error(e);
        }
    });

    socket.on('play-video', async ({ groupId, videoId }) => {
        try {
            await db.run('UPDATE groups SET current_video = ? WHERE groupId = ?', [videoId, groupId]);
            io.to(groupId).emit('sync-video', { videoId });
        } catch(e) {
            console.error(e);
        }
    });

    socket.on('private-message', async ({ to, from, text }) => {
        try {
            const serverTime = getISTTime();
            await db.run('INSERT INTO private_messages (from_user, to_user, text, time) VALUES (?, ?, ?, ?)',
                [from, to, text, serverTime]);
            
            let targetSocketId = null;
            for (let [id, username] of onlineUsers.entries()) {
                if (username === to) {
                    targetSocketId = id;
                    break;
                }
            }
            
            const messageData = { from, text, time: serverTime };
            if (targetSocketId) {
                io.to(targetSocketId).emit('private-message', messageData);
            }
            socket.emit('private-message-sent', { to, text, time: serverTime });
        } catch(e) {
            console.error(e);
        }
    });

    socket.on('profile-pic-updated', async ({ userId, imageData }) => {
        try {
            await db.run('UPDATE users SET profile_pic = ? WHERE username = ?', [imageData, userId]);
            if (currentGroup) {
                socket.to(currentGroup).emit('profile-pic-updated', { userId, imageData });
            }
        } catch(e) {
            console.error(e);
        }
    });

    socket.on('leave-group', async ({ groupId, userId }) => {
        try {
            await db.run('DELETE FROM group_members WHERE groupId = ? AND username = ?', [groupId, userId]);
            socket.leave(groupId);
            if (currentGroup === groupId) currentGroup = null;
            updateOnlineUsers(groupId);
        } catch(e) {
            console.error(e);
        }
    });

    socket.on('close-group', async ({ groupId }) => {
        try {
            await db.run('DELETE FROM group_members WHERE groupId = ?', [groupId]);
            await db.run('DELETE FROM groups WHERE groupId = ?', [groupId]);
            io.to(groupId).emit('group-closed');
            const roomSockets = await io.in(groupId).fetchSockets();
            for (const s of roomSockets) {
                s.leave(groupId);
            }
        } catch(e) {
            console.error(e);
        }
    });

    socket.on('disconnect', () => {
        if (currentUser) onlineUsers.delete(socket.id);
        if (currentGroup && currentUser) {
            updateOnlineUsers(currentGroup);
        }
    });
    
    async function updateOnlineUsers(groupId) {
        try {
            const roomSockets = await io.in(groupId).fetchSockets();
            const users = [];
            for (const s of roomSockets) {
                if (s.username) users.push(s.username);
            }
            io.to(groupId).emit('online-users', [...new Set(users)]);
        } catch(e) {
            console.error(e);
        }
    }
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
