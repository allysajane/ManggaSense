
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const db = require('./db');

require('dotenv').config();

const app = express();


// =========================
// MIDDLEWARE
// =========================

app.use(express.json());
app.use(express.urlencoded({ extended: true }));


// =========================
// SESSION CONFIGURATION
// =========================

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 2
    }
}));


// =========================
// PROTECTED PAGE ROUTES
// =========================

// PROTECT DASHBOARD PAGE
app.get('/dashboard.html', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/');
    }

    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});


// PROTECT MANGO GRADING PAGE
app.get('/mango-grading.html', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/');
    }

    res.sendFile(
        path.join(__dirname, 'public', 'mango-grading.html')
    );
});


// PROTECT MANGO RECORDS PAGE
app.get('/mango-records.html', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/');
    }

    res.sendFile(
        path.join(__dirname, 'public', 'mango-records.html')
    );
});


// PROTECT HARVEST ALERTS PAGE
app.get('/harvest-alerts.html', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/');
    }

    res.sendFile(
        path.join(__dirname, 'public', 'harvest-alerts.html')
    );
});


// PROTECT MANGO MONITORING PAGE
app.get('/mango-monitoring.html', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/');
    }

    res.sendFile(
        path.join(__dirname, 'public', 'mango-monitoring.html')
    );
});


// =========================
// DATABASE HEALTH CHECK
// =========================

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
            message: 'Database connection failed'
        });
    }
});


// =========================
// USER REGISTRATION
// =========================

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
            });
        }

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

        const passwordHash = await bcrypt.hash(password, 12);

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


// =========================
// USER LOGIN
// =========================

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

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


// =========================
// CHECK CURRENT LOGIN SESSION
// =========================

app.get('/api/me', (req, res) => {
    if (!req.session.user) {
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


// =========================
// SAVE MANGO GRADING RECORD
// =========================

app.post('/api/mango-grading', async (req, res) => {
    try {
        if (!req.session.user) {
            return res.status(401).json({
                success: false,
                message: 'Please log in to submit a mango grading record.'
            });
        }

        const {
            mango_variety,
            weight,
            maturity_level,
            skin_color,
            defects,
            quality_grade
        } = req.body;

        if (
            !mango_variety ||
            weight === undefined ||
            weight === null ||
            weight === '' ||
            !maturity_level ||
            !skin_color ||
            !quality_grade
        ) {
            return res.status(400).json({
                success: false,
                message: 'Please complete all required grading fields.'
            });
        }

        const cleanVariety = String(mango_variety).trim();
        const cleanMaturity = String(maturity_level).trim();
        const cleanSkinColor = String(skin_color).trim();
        const cleanGrade = String(quality_grade).trim();

        const mangoWeight = Number(weight);

        if (
            !cleanVariety ||
            !cleanMaturity ||
            !cleanSkinColor ||
            !cleanGrade ||
            cleanVariety.length > 100 ||
            !Number.isFinite(mangoWeight) ||
            mangoWeight <= 0 ||
            mangoWeight > 99999999
        ) {
            return res.status(400).json({
                success: false,
                message: 'Please enter valid mango grading information.'
            });
        }

        await db.query(
            `INSERT INTO mango_grading
            (user_id, mango_variety, weight, maturity_level, skin_color, defects, quality_grade)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                req.session.user.id,
                cleanVariety,
                mangoWeight,
                cleanMaturity,
                cleanSkinColor,
                defects ? String(defects).trim() : null,
                cleanGrade
            ]
        );

        res.status(201).json({
            success: true,
            message: 'Mango grading record saved successfully!'
        });

    } catch (error) {
        console.error('Mango grading error:', error);

        res.status(500).json({
            success: false,
            message: 'Unable to save mango grading record.'
        });
    }
});


// =========================
// GET MANGO GRADING RECORDS
// =========================

app.get('/api/mango-grading', async (req, res) => {
    try {
        if (!req.session.user) {
            return res.status(401).json({
                success: false,
                message: 'Please log in to view grading records.'
            });
        }

        const [records] = await db.query(
            `SELECT
                id,
                mango_variety,
                weight,
                maturity_level,
                skin_color,
                defects,
                quality_grade,
                created_at
            FROM mango_grading
            WHERE user_id = ?
            ORDER BY created_at DESC`,
            [req.session.user.id]
        );

        res.json({
            success: true,
            records: records
        });

    } catch (error) {
        console.error('Retrieve grading records error:', error);

        res.status(500).json({
            success: false,
            message: 'Unable to retrieve mango grading records.'
        });
    }
});


// =========================
// SAVE MANGO MONITORING RECORD
// =========================

app.post('/api/mango-monitoring', async (req, res) => {
    try {
        if (!req.session.user) {
            return res.status(401).json({
                success: false,
                message: 'Please log in to save a monitoring record.'
            });
        }

        const {
            mango_variety,
            tree_condition,
            growth_stage,
            observation_date,
            remarks
        } = req.body;

        if (
            !mango_variety ||
            !tree_condition ||
            !growth_stage ||
            !observation_date
        ) {
            return res.status(400).json({
                success: false,
                message: 'Please complete all required fields.'
            });
        }

        const cleanVariety = String(mango_variety).trim();
        const cleanCondition = String(tree_condition).trim();
        const cleanStage = String(growth_stage).trim();
        const cleanDate = String(observation_date).trim();
        const cleanRemarks = remarks ? String(remarks).trim() : null;

        if (
            cleanVariety.length > 100 ||
            cleanCondition.length > 50 ||
            cleanStage.length > 50 ||
            !/^\d{4}-\d{2}-\d{2}$/.test(cleanDate) ||
            Number.isNaN(Date.parse(cleanDate + 'T00:00:00'))
        ) {
            return res.status(400).json({
                success: false,
                message: 'Please enter valid monitoring information.'
            });
        }

        await db.query(
            `INSERT INTO mango_monitoring
            (user_id, mango_variety, tree_condition, growth_stage, observation_date, remarks)
            VALUES (?, ?, ?, ?, ?, ?)`,
            [
                req.session.user.id,
                cleanVariety,
                cleanCondition,
                cleanStage,
                cleanDate,
                cleanRemarks
            ]
        );

        res.status(201).json({
            success: true,
            message: 'Monitoring record saved successfully!'
        });

    } catch (error) {
        console.error('Mango monitoring error:', error);

        res.status(500).json({
            success: false,
            message: 'Unable to save monitoring record.'
        });
    }
});


// =========================
// GET MANGO MONITORING RECORDS
// =========================

app.get('/api/mango-monitoring', async (req, res) => {
    try {
        if (!req.session.user) {
            return res.status(401).json({
                success: false,
                message: 'Please log in to view monitoring records.'
            });
        }

        const [records] = await db.query(
            `SELECT
                id,
                mango_variety,
                tree_condition,
                growth_stage,
                observation_date,
                remarks,
                created_at
            FROM mango_monitoring
            WHERE user_id = ?
            ORDER BY observation_date DESC, id DESC`,
            [req.session.user.id]
        );

        res.json({
            success: true,
            records: records
        });

    } catch (error) {
        console.error('Retrieve monitoring records error:', error);

        res.status(500).json({
            success: false,
            message: 'Unable to retrieve monitoring records.'
        });
    }
});


// =========================
// USER LOGOUT
// =========================

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


// =========================
// SERVE PUBLIC FILES
// Keep this AFTER protected pages and API routes
// =========================

app.use(express.static(path.join(__dirname, 'public')));


// =========================
// START SERVER
// =========================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`ManggaSense running at http://localhost:${PORT}`);
});
