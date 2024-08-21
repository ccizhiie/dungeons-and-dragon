const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
const secret = 'D0pWPzBwPn'; // Use a secure secret key

// Setup middleware
app.use(bodyParser.json());
app.use(cors());

// MySQL connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'dungeon_and_dragons'
});

db.connect((err) => {
    if (err) throw err;
    console.log('Connected to MySQL database.');
});

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (token == null) return res.sendStatus(401); // No token

    jwt.verify(token, secret, (err, user) => {
        if (err) return res.sendStatus(403); // Invalid token
        req.user = user;
        next();
    });
}

// Register a new user
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const query = 'INSERT INTO users (username, password) VALUES (?, ?)';
    db.query(query, [username, hashedPassword], (err, result) => {
        if (err) {
            return res.status(400).json({ message: 'Username already exists.' });
        }
        res.json({ message: 'User registered successfully!' });
    });
});

// Login
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const query = 'SELECT * FROM users WHERE username = ?';
    db.query(query, [username], async (err, results) => {
        if (err || results.length === 0) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const user = results[0];
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        // Generate JWT token
        const token = jwt.sign({ id: user.id, username: user.username }, secretKey, { expiresIn: '1h' });
        res.json({ token });
    });
});

// Host a game
app.post('/host-game', authenticateToken, async (req, res) => {
    const { host } = req.body;
    const roomCode = generateRoomCode();
    try {
        await db.query('INSERT INTO lobbies (roomCode, host) VALUES (?, ?)', [roomCode, host]);
        res.json({ roomCode });
    } catch (error) {
        res.status(500).json({ message: 'Error hosting game.' });
    }
});

// Join a game
app.post('/join-game', authenticateToken, (req, res) => {
    const { roomCode, playerName } = req.body;

    const query = 'SELECT id FROM games WHERE room_code = ?';
    db.query(query, [roomCode], (err, results) => {
        if (err || results.length === 0) {
            return res.status(404).json({ message: 'Game not found.' });
        }

        const gameId = results[0].id;
        const insertPlayerQuery = 'INSERT INTO players (game_id, player_name) VALUES (?, ?)';
        db.query(insertPlayerQuery, [gameId, playerName], (err, result) => {
            if (err) {
                return res.status(500).json({ message: 'Error joining game.' });
            }
            res.json({ message: 'Joined game successfully!' });
        });
    });
});

// Fetch the list of players in a game
app.post('/get-players', authenticateToken, (req, res) => {
    const { roomCode } = req.body;

    const query = `
        SELECT player_name, ready 
        FROM players 
        WHERE game_id = (SELECT id FROM games WHERE room_code = ?)`;

    db.query(query, [roomCode], (err, results) => {
        if (err) {
            return res.status(500).json({ message: 'Error fetching players.' });
        }

        const allReady = results.every(player => player.ready);
        res.json({ players: results, allReady });
    });
});


// Toggle ready status
app.post('/toggle-ready', authenticateToken, (req, res) => {
    const { roomCode, playerName } = req.body;

    const query = `
        UPDATE players 
        SET ready = NOT ready 
        WHERE player_name = ? 
        AND game_id = (SELECT id FROM games WHERE room_code = ?)`;

    db.query(query, [playerName, roomCode], (err, result) => {
        if (err) {
            return res.status(500).json({ message: 'Error toggling ready status.' });
        }

        const checkAllReadyQuery = `
            SELECT ready FROM players 
            WHERE game_id = (SELECT id FROM games WHERE room_code = ?)`;

        db.query(checkAllReadyQuery, [roomCode], (err, results) => {
            if (err) {
                return res.status(500).json({ message: 'Error checking ready status.' });
            }

            const allReady = results.every(player => player.ready);
            res.json({ allReady });
        });
    });
});

// Start the game
app.post('/start-game', authenticateToken, (req, res) => {
    const { roomCode } = req.body;

    const query = 'SELECT host_id FROM games WHERE room_code = ?';
    db.query(query, [roomCode], (err, results) => {
        if (err || results.length === 0) {
            return res.status(404).json({ message: 'Game not found.' });
        }

        if (results[0].host_id !== req.user.id) {
            return res.status(403).json({ message: 'Only the host can start the game.' });
        }

        // Proceed to start the game if all conditions are met
        res.json({ message: 'Game started successfully!' });
    });
});

// Serve static files (assuming your front-end files are in the 'public' directory)
app.use(express.static('public'));

// Start the server
app.listen(5000, () => {
    console.log('Server running on http://localhost:5000');
});
