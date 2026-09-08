const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 3000;

app.use(express.json());

/*
Serve the website
*/

app.use(
    express.static(
        path.join(__dirname, "public")
    )
);


/*
PostgreSQL database
*/

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,

    ssl: {
        rejectUnauthorized: false
    }
});


/*
Create users table
*/

async function createUsersTable() {

    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (

            id SERIAL PRIMARY KEY,

            name VARCHAR(100) NOT NULL,

            email VARCHAR(255)
                UNIQUE NOT NULL,

            password_hash TEXT NOT NULL,

            created_at
                TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);

}


/*
Register
*/

app.post("/api/register", async (req, res) => {

    try {

        const {
            name,
            email,
            password
        } = req.body;


        if (
            !name ||
            !email ||
            !password
        ) {

            return res.status(400).json({
                message:
                    "All fields are required."
            });

        }


        if (password.length < 8) {

            return res.status(400).json({
                message:
                    "Password must contain at least 8 characters."
            });

        }


        const passwordHash =
            await bcrypt.hash(
                password,
                12
            );


        const result =
            await pool.query(
                `
                INSERT INTO users
                (name, email, password_hash)

                VALUES ($1, $2, $3)

                RETURNING
                id,
                name,
                email
                `,
                [
                    name,
                    email.toLowerCase(),
                    passwordHash
                ]
            );


        res.status(201).json({

            message:
                "Account created successfully.",

            user:
                result.rows[0]

        });


    } catch (error) {

        if (
            error.code === "23505"
        ) {

            return res.status(409).json({
                message:
                    "Email is already registered."
            });

        }


        console.error(error);

        res.status(500).json({
            message:
                "Server error."
        });

    }

});


/*
Login
*/

app.post("/api/login", async (req, res) => {

    try {

        const {
            email,
            password
        } = req.body;


        const result =
            await pool.query(
                `
                SELECT *
                FROM users
                WHERE email = $1
                `,
                [
                    email.toLowerCase()
                ]
            );


        if (
            result.rows.length === 0
        ) {

            return res.status(401).json({
                message:
                    "Invalid email or password."
            });

        }


        const user =
            result.rows[0];


        const passwordCorrect =
            await bcrypt.compare(
                password,
                user.password_hash
            );


        if (!passwordCorrect) {

            return res.status(401).json({
                message:
                    "Invalid email or password."
            });

        }


        res.json({

            message:
                "Login successful.",

            user: {

                id: user.id,

                name: user.name,

                email: user.email

            }

        });


    } catch (error) {

        console.error(error);

        res.status(500).json({
            message:
                "Server error."
        });

    }

});


/*
Health check
*/

app.get("/api/health", async (req, res) => {

    try {

        await pool.query(
            "SELECT 1"
        );

        res.json({
            status: "OK",
            database: "connected"
        });

    } catch {

        res.status(500).json({
            status: "ERROR",
            database: "not connected"
        });

    }

});


/*
Start server
*/

createUsersTable()
    .then(() => {

        app.listen(
            PORT,
            () => {

                console.log(
                    `Server running on port ${PORT}`
                );

            }
        );

    })
    .catch(error => {

        console.error(
            "Database error:",
            error
        );

        process.exit(1);

    });
