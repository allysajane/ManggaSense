const db = require('./db');

async function testConnection() {
    let connection;

    try {
        connection = await db.getConnection();

        console.log('Successfully connected to MySQL!');

        const [rows] = await connection.query(
            'SELECT DATABASE() AS database_name'
        );

        console.log('Connected database:', rows[0].database_name);

    } catch (error) {
        console.error('Database connection failed:', error.message);
        process.exitCode = 1;

    } finally {
        if (connection) connection.release();
        await db.end();
    }
}

testConnection();