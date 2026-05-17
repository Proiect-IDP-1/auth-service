const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const promClient = require('prom-client');

const app = express();
app.use(express.json());

// ----- Prometheus metrics -----
const register = new promClient.Registry();
promClient.collectDefaultMetrics({ register });
const httpRequestCounter = new promClient.Counter({
    name: 'auth_requests_total',
    help: 'Total HTTP requests to auth service',
    labelNames: ['method', 'route', 'status'],
    registers: [register],
});
const httpRequestDuration = new promClient.Histogram({
    name: 'auth_request_duration_seconds',
    help: 'HTTP request duration',
    labelNames: ['method', 'route'],
    registers: [register],
});
app.use((req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: req.method, route: req.path });
    res.on('finish', () => {
        httpRequestCounter.inc({ method: req.method, route: req.path, status: res.statusCode });
        end();
    });
    next();
});

// ----- DB pool with retry -----
const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgres://user:password@auth-db:5432/auth_db',
});

const JWT_SECRET = process.env.JWT_SECRET || 'secret';

// ----- Routes -----
app.post('/auth/register', async (req, res) => {
    const { username, password, email } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'username and password required' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (username, password, email) VALUES ($1, $2, $3) RETURNING id',
            [username, hashedPassword, email || `${username}@tabletop.ro`]
        );
        console.log(`[auth] Registered user id=${result.rows[0].id} username=${username}`);
        res.status(201).json({ message: 'User registered successfully', id: result.rows[0].id });
    } catch (err) {
        console.error('[auth] Registration error:', err.message);
        if (err.code === '23505') {
            return res.status(409).json({ error: 'Username already exists' });
        }
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'username and password required' });
    }
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];
        if (user && (await bcrypt.compare(password, user.password))) {
            const token = jwt.sign(
                { id: user.id, username: user.username, email: user.email },
                JWT_SECRET,
                { expiresIn: '1h' }
            );
            console.log(`[auth] Login OK username=${username}`);
            res.json({ token });
        } else {
            res.status(401).json({ error: 'Invalid username or password' });
        }
    } catch (err) {
        console.error('[auth] Login error:', err.message);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Verify token endpoint - used by other services via Kong
app.get('/auth/verify', (req, res) => {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
        const data = jwt.verify(token, JWT_SECRET);
        res.json({ valid: true, user: data });
    } catch (e) {
        res.status(401).json({ valid: false, error: e.message });
    }
});

app.get('/health', (req, res) => res.json({ status: 'Auth Service is Up!', service: 'auth' }));

app.get('/metrics', async (req, res) => {
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Auth service running on port ${PORT}`));
