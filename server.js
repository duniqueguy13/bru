const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const path = require('path');
const http = require('http');
const WebSocket = require('ws');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(cors());
app.use(helmet());

// MongoDB Atlas Connection
const mongoURI = 'mongodb+srv://bruthaofficial:Mikrlo123god@bruthacluster.klccx.mongodb.net/?retryWrites=true&w=majority&appName=Bruthacluster';
mongoose.connect(mongoURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
    .then(() => console.log('Connected to MongoDB Atlas'))
    .catch(err => console.error('MongoDB Atlas connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'user' }, // 'user', 'moderator', 'admin'
    isBanned: { type: Boolean, default: false },
    restrictedUntil: { type: Date, default: null },
    accessibleAreas: { type: [String], default: ['public'] } // e.g., ['public', 'vip-lounge']
});
const User = mongoose.model('User', userSchema);

// Post Schema
const postSchema = new mongoose.Schema({
    user: { type: String, required: true },
    content: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    likes: { type: Number, default: 0 },
    likedBy: { type: [String], default: [] },
    comments: [{
        user: { type: String, required: true },
        content: { type: String, required: true },
        timestamp: { type: Date, default: Date.now }
    }]
});
const Post = mongoose.model('Post', postSchema);

// Discussion Message Schema
const discussionMessageSchema = new mongoose.Schema({
    discussionId: { type: String, required: true },
    user: { type: String, required: true },
    content: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    likes: { type: Number, default: 0 },
    likedBy: { type: [String], default: [] },
    comments: [{
        user: { type: String, required: true },
        content: { type: String, required: true },
        timestamp: { type: Date, default: Date.now }
    }]
});
const DiscussionMessage = mongoose.model('DiscussionMessage', discussionMessageSchema);

// DM Schema
const dmSchema = new mongoose.Schema({
    sender: { type: String, required: true },
    receiver: { type: String, required: true },
    content: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    read: { type: Boolean, default: false }
});
const DM = mongoose.model('DM', dmSchema);

// Secret for JWT (replace with a secure key in production)
const JWT_SECRET = 'your-secret-key';

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Middleware to Check User Restrictions
const checkRestrictions = async (req, res, next) => {
    try {
        const user = await User.findOne({ username: req.user.username });
        if (!user) return res.status(404).json({ error: 'User not found' });

        if (user.isBanned) return res.status(403).json({ error: 'User is banned' });
        if (user.restrictedUntil && new Date() < user.restrictedUntil) {
            return res.status(403).json({ error: 'User is restricted until ' + user.restrictedUntil });
        }
        req.user.role = user.role; // Add role to req.user for admin checks
        req.user.id = user._id; // Add user ID for admin routes
        next();
    } catch (err) {
        console.error('Error checking restrictions:', err);
        res.status(500).json({ error: 'Server error' });
    }
};

// WebSocket Connection for DMs
wss.on('connection', (ws) => {
    console.log('New WebSocket client connected');

    ws.on('message', async (data) => {
        const msg = JSON.parse(data);
        if (msg.type === 'init') {
            const messages = await DM.find({
                $or: [{ sender: msg.username }, { receiver: msg.username }]
            }).sort({ timestamp: -1 });
            ws.send(JSON.stringify({ type: 'init', messages }));
        } else if (msg.type === 'send') {
            const newMessage = new DM({
                sender: msg.sender,
                receiver: msg.receiver,
                content: msg.content
            });
            await newMessage.save();
            wss.clients.forEach(client => {
                if (client.readyState === WebSocket.OPEN) {
                    client.send(JSON.stringify({ type: 'new_message', message: newMessage }));
                }
            });
        } else if (msg.type === 'read') {
            await DM.updateOne({ _id: msg.messageId }, { read: true });
            wss.clients.forEach(client => {
                if (client.readyState === WebSocket.OPEN) {
                    client.send(JSON.stringify({ type: 'update_message', messageId: msg.messageId, read: true }));
                }
            });
        }
    });

    ws.on('close', () => console.log('WebSocket client disconnected'));
});

// Routes for User Authentication
app.post('/register', [
    body('username').notEmpty().trim().withMessage('Username is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { username, password } = req.body;

    try {
        const existingUser = await User.findOne({ username });
        if (existingUser) return res.status(400).json({ error: 'Username already taken' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, password: hashedPassword });
        await user.save();

        // Send welcome DM
        const welcomeMessage = new DM({
            sender: 'The Bruthahood',
            receiver: username,
            content: 'Welcome to the Bruthahood Community! We’re thrilled to have you here. Dive into the discussions, connect with others, and make yourself at home.'
        });
        await welcomeMessage.save();

        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        console.error('Error registering user:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/login', [
    body('username').notEmpty().trim().withMessage('Username is required'),
    body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ error: 'Invalid credentials' });

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).json({ error: 'Invalid credentials' });

        if (user.isBanned) return res.status(403).json({ error: 'User is banned' });

        const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, username: user.username }); // Include username in response
    } catch (err) {
        console.error('Error logging in:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Routes for Posts
app.get('/posts', authenticateToken, checkRestrictions, async (req, res) => {
    try {
        const posts = await Post.find().sort({ timestamp: -1 });
        res.json(posts);
    } catch (err) {
        console.error('Error fetching posts:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/posts', authenticateToken, checkRestrictions, [
    body('content').notEmpty().trim().withMessage('Content is required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { content } = req.body;
    const post = new Post({
        user: req.user.username,
        content
    });

    try {
        await post.save();
        res.status(201).json(post);
    } catch (err) {
        console.error('Error saving post:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/posts/:id/like', authenticateToken, checkRestrictions, [
    body('action').isIn(['like', 'unlike']).withMessage('Action must be "like" or "unlike"')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { id } = req.params;
    const { action } = req.body;

    try {
        const post = await Post.findById(id);
        if (!post) return res.status(404).json({ error: 'Post not found' });

        if (action === 'like') {
            if (!post.likedBy.includes(req.user.username)) {
                post.likes += 1;
                post.likedBy.push(req.user.username);
            }
        } else if (action === 'unlike') {
            if (post.likedBy.includes(req.user.username)) {
                post.likes -= 1;
                post.likedBy = post.likedBy.filter(user => user !== req.user.username);
            }
        }
        await post.save();
        res.json(post);
    } catch (err) {
        console.error('Error updating like:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/posts/:id/comment', authenticateToken, checkRestrictions, [
    body('content').notEmpty().trim().withMessage('Comment content is required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { id } = req.params;
    const { content } = req.body;

    try {
        const post = await Post.findById(id);
        if (!post) return res.status(404).json({ error: 'Post not found' });

        post.comments.push({ user: req.user.username, content });
        await post.save();
        res.status(201).json(post);
    } catch (err) {
        console.error('Error posting comment:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/posts/:id/comments', authenticateToken, checkRestrictions, async (req, res) => {
    const { id } = req.params;

    try {
        const post = await Post.findById(id);
        if (!post) return res.status(404).json({ error: 'Post not found' });
        res.json(post.comments);
    } catch (err) {
        console.error('Error fetching comments:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Routes for Discussion Messages
app.get('/discussions/:id/messages', authenticateToken, checkRestrictions, async (req, res) => {
    const { id } = req.params;

    try {
        const messages = await DiscussionMessage.find({ discussionId: id }).sort({ timestamp: 1 });
        res.json(messages);
    } catch (err) {
        console.error('Error fetching messages:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/discussions/:id/messages', authenticateToken, checkRestrictions, [
    body('content').notEmpty().trim().withMessage('Message content is required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { id } = req.params;
    const { content } = req.body;

    try {
        const message = new DiscussionMessage({ discussionId: id, user: req.user.username, content });
        await message.save();
        res.status(201).json(message);
    } catch (err) {
        console.error('Error posting message:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/discussions/:discussionId/messages/:messageId/like', authenticateToken, checkRestrictions, [
    body('action').isIn(['like', 'unlike']).withMessage('Action must be "like" or "unlike"')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { messageId } = req.params;
    const { action } = req.body;

    try {
        const message = await DiscussionMessage.findById(messageId);
        if (!message) return res.status(404).json({ error: 'Message not found' });

        if (action === 'like') {
            if (!message.likedBy.includes(req.user.username)) {
                message.likes += 1;
                message.likedBy.push(req.user.username);
            }
        } else if (action === 'unlike') {
            if (message.likedBy.includes(req.user.username)) {
                message.likes -= 1;
                message.likedBy = message.likedBy.filter(user => user !== req.user.username);
            }
        }
        await message.save();
        res.json(message);
    } catch (err) {
        console.error('Error updating like:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/discussions/:discussionId/messages/:messageId/comment', authenticateToken, checkRestrictions, [
    body('content').notEmpty().trim().withMessage('Comment content is required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { messageId } = req.params;
    const { content } = req.body;

    try {
        const message = await DiscussionMessage.findById(messageId);
        if (!message) return res.status(404).json({ error: 'Message not found' });

        message.comments.push({ user: req.user.username, content });
        await message.save();
        res.status(201).json(message);
    } catch (err) {
        console.error('Error posting comment:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/discussions/:discussionId/messages/:messageId/comments', authenticateToken, checkRestrictions, async (req, res) => {
    const { messageId } = req.params;

    try {
        const message = await DiscussionMessage.findById(messageId);
        if (!message) return res.status(404).json({ error: 'Message not found' });
        res.json(message.comments);
    } catch (err) {
        console.error('Error fetching comments:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// DM Routes
app.get('/dms/:username', authenticateToken, checkRestrictions, async (req, res) => {
    const { username } = req.params;
    try {
        const messages = await DM.find({
            $or: [
                { sender: req.user.username, receiver: username },
                { sender: username, receiver: req.user.username }
            ]
        }).sort({ timestamp: 1 });
        res.json(messages);
    } catch (err) {
        console.error('Error fetching DMs:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Admin Routes for User Management
app.post('/admin/restrict-user', authenticateToken, checkRestrictions, [
    body('userId').notEmpty().trim().withMessage('User ID is required'),
    body('days').isInt({ min: 1 }).withMessage('Days must be a positive integer')
], async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });

    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { userId, days } = req.body;

    try {
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });

        user.restrictedUntil = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
        await user.save();
        res.json({ message: `User restricted for ${days} days` });
    } catch (err) {
        console.error('Error restricting user:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/admin/ban-user', authenticateToken, checkRestrictions, [
    body('userId').notEmpty().trim().withMessage('User ID is required')
], async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });

    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { userId } = req.body;

    try {
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });

        user.isBanned = true;
        await user.save();
        res.json({ message: 'User banned' });
    } catch (err) {
        console.error('Error banning user:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/admin/unban-user', authenticateToken, checkRestrictions, [
    body('userId').notEmpty().trim().withMessage('User ID is required')
], async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });

    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { userId } = req.body;

    try {
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });

        user.isBanned = false;
        user.restrictedUntil = null;
        await user.save();
        res.json({ message: 'User unbanned' });
    } catch (err) {
        console.error('Error unbanning user:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.delete('/admin/delete-post/:id', authenticateToken, checkRestrictions, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });

    const { id } = req.params;

    try {
        const post = await Post.findByIdAndDelete(id);
        if (!post) return res.status(404).json({ error: 'Post not found' });

        res.json({ message: 'Post deleted' });
    } catch (err) {
        console.error('Error deleting post:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/admin/assign-access', authenticateToken, checkRestrictions, [
    body('userId').notEmpty().trim().withMessage('User ID is required'),
    body('area').notEmpty().trim().withMessage('Area is required')
], async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });

    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { userId, area } = req.body;

    try {
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });

        if (!user.accessibleAreas.includes(area)) {
            user.accessibleAreas.push(area);
            await user.save();
        }
        res.json({ message: `Access to ${area} granted` });
    } catch (err) {
        console.error('Error assigning access:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/admin/revoke-access', authenticateToken, checkRestrictions, [
    body('userId').notEmpty().trim().withMessage('User ID is required'),
    body('area').notEmpty().trim().withMessage('Area is required')
], async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });

    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { userId, area } = req.body;

    try {
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });

        user.accessibleAreas = user.accessibleAreas.filter(a => a !== area);
        await user.save();
        res.json({ message: `Access to ${area} revoked` });
    } catch (err) {
        console.error('Error revoking access:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/user/access', authenticateToken, async (req, res) => {
    try {
        const user = await User.findOne({ username: req.user.username });
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json({ accessibleAreas: user.accessibleAreas });
    } catch (err) {
        console.error('Error fetching user access:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Start the Server
server.listen(3000, () => {
    console.log('Server running at http://localhost:3000');
});