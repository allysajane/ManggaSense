const express = require('express');
const db = require('./db');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

//Test the application and database
app.get('/api/health', async (req, res) => {
    try {
        await db.query('SELECT 1');

        res.json({
            status: 'success',
            message: 'ManggaSense is running!',
            database: 'Connected to manggasense'
        })
    } catch (error) {
        console.error(error);

        res.status(500).json({
            status: 'error',
            message: 'Database connection failed'
        });
    }
});

// Start the server
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`ManggaSense running at http://localhost:${PORT}`);
});