const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const pool = new Pool({
	connectionString: process.env.DATABASE_URL || 'postgres://user:password@auth-db:5432/auth_db'
});

const JWT_SECRET = process.env.JWT_SECRET || 'secret';


// Register
app.post('/auth/register', async (req, res) => {
	const { username, password } = req.body;

	try {
		const hashedPassword = await bcrypt.hash(password, 10);
		await pool.query(
			'INSERT INTO users (username, password) VALUES ($1, $2)',
			[username, hashedPassword]
		);
		res.status(201).json({ message: "User registered successfully" });
	} catch (err) {
		res.status(500).json({ error: "Registration failed" });
	}
});


// Login
app.post('/auth/login', async (req, res) => {
	const { username, password } = req.body;

	try {
		const result = await pool.query(
			'SELECT * FROM users WHERE username = $1',
			[username]
		);
		const user = result.rows[0];

		if (user && await bcrypt.compare(password, user.password)) {
			const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
			res.json({ token });
		} else {
			res.status(401).json({ error: "Invalid username or password" });
		}
	} catch (err) {
		res.status(500).json({ error: "Login failed" });
	}
});


// Health check
app.get('/health', (req, res) => res.send('OK'));


const PORT = 3000;
app.listen(PORT, () => {
	console.log(`Auth service running on port ${PORT}`);
});
