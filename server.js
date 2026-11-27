const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const db = require('./db');

require('dotenv').config();

const app = express();


// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false, // For Localhost development
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 2
    }
}));

// PROTECT DASHBOARD PAGE
app.get('/dashboard.html', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/');
    }

    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Serve public files AFTER dashboard protection
app.use(express.static(path.join(__dirname, 'public')));


// DATABASE AND SERVER HEALTH CHECK
app.get('/api/health', async (req, res) => {
    try {
        await db.query('SELECT 1');

        res.json({
            status: 'success',
            message: 'ManggaSense is running!',
            database: 'Connected to manggasense'
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            status: 'error',
            message: 'Database connection failed',
        });
    }
});

// USER REGISTRATION
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, confirmPassword } = req.body;

        if (!name || !email || !password || !confirmPassword) {
            return res.status(400).json({
                success: false,
                message: 'Please complete all required fields.'
            });
        }

        const cleanName = name.trim();
        const cleanEmail = email.trim().toLowerCase();

        if (cleanName.length > 100) {
            return res.status(400).json({
                success: false,
                message: 'Full name must not exceed 100 characters.'
            });
        }

        if (cleanEmail.length > 150) {
            return res.status(400).json({
                success: false,
                message: 'Email address is too long.'
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                success: false,
                message: 'Password must contain at least 8 characters.'
            });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({
                success: false,
                message: 'Passwords do not match.'
            })
        }

        // Check if email already exists
        const [existingUsers] = await db.query(
            'SELECT id FROM users WHERE email = ?',
            [cleanEmail]
        );

        if (existingUsers.length > 0) {
            return res.status(409).json({
                success: false,
                message: 'This email address is already registered.'
            });
        }

        // Hash password
        const passwordHash = await bcrypt.hash(password, 12);

        // Insert new grower account
        await db.query(
            'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
            [cleanName, cleanEmail, passwordHash]
        );

        res.status(201).json({
            success: true,
            message: 'Your account has been created successfully. You can now log in.'
        });

    } catch (error) {
        console.error('Registration error:', error);

        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({
                success: false,
                message: 'This email address is already registered.'
            });
        }

        res.status(500).json({
            success: false,
            message: 'Registration failed. Please try again.'
        });
    }
});

// USER LOGIN
app.post('/api/login', async (req, res) => {
    try {
        const {email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Please enter your email and password.'
            });
        }

        const cleanEmail = email.trim().toLowerCase();

        const [users] = await db.query(
            'SELECT * FROM users WHERE email = ?',
            [cleanEmail]
        );

        if (users.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password.'
            });
        }

        const user = users[0];

        // Compare entered password with stored hash
        const passwordMatch = await bcrypt.compare(
            password,
            user.password_hash
        );

        if (!passwordMatch) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password.'
            });
        }

        // Regenerate session after successful login
        req.session.regenerate((error) => {
            if (error) {
                console.error('Session error:', error);

                return res.status(500).json({
                    success: false,
                    message: 'Unable to start your session.'
                });
            }

            req.session.user = {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            };

            req.session.save((saveError) => {
                if (saveError) {
                    console.error('Session save error:', saveError);

                    return res.status(500).json({
                        success: false,
                        message: 'Unable to save your session.'
                    });
                }

                res.json({
                    success: true,
                    message: 'Login successful!',
                    user: req.session.user
                });
            });
        });

    } catch (error) {
        console.error('Login error:', error);

        res.status(500).json({
            success: false,
            message: 'Login failed. Please try again.'
        });
    }
});

// CHECK CURRENT LOGIN SESSION
app.get('/api/me', (req, res) => {
    if(!req.session.user) {
        return res.status(401).json({
            success: false,
            message: 'You are not logged in.'
        });
    }

    res.json({
        success: true,
        user: req.session.user
    });
});

// USER LOGOUT
app.post('/api/logout', (req, res) => {
    req.session.destroy((error) => {
        if (error) {
            return res.status(500).json({
                success: false,
                message: 'Unable to log out.'
            });
        }

        res.clearCookie('connect.sid');

        res.json({
            success: true,
            message: 'You have logged out successfully.'
        });
    });
});

// START SERVER
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`ManggaSense running at http://localhost:${PORT}`);
});