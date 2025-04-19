const express = require("express");
const mysql2 = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

// Database connection
const db = mysql2.createPool({
    host: "localhost",
    user: "root",
    password: "",
    database: "earist",
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
});

db.getConnection((err, connection) => {
    if (err) {
        console.error("Database connection failed:", err);
    } else {
        console.log("Connected to MySQL database");
        connection.release(); // Release the connection back to the pool
    }
});

// Middleware to authenticate JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: "Unauthorized: No token provided" });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: "Forbidden: Invalid token" });
        req.user = user; // Attach user data to the request
        next();
    });
};

// Register
app.post("/register", async (req, res) => {
    const { username, password, role } = req.body;

    if (!username || !password || !role) {
        return res.status(400).json({ message: "All fields are required" });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const [existingUser] = await db.promise().query("SELECT * FROM users WHERE username = ?", [username]);
        if (existingUser.length > 0) {
            return res.status(400).json({ message: "User already exists" });
        }

        await db.promise().query("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [username, hashedPassword, role]);
        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        console.error("Registration error:", error);
        res.status(500).json({ message: "Registration failed" });
    }
});

// Login
app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: "All fields are required" });
    }

    try {
        const [results] = await db.promise().query("SELECT * FROM users WHERE username = ?", [username]);
        if (results.length === 0) {
            return res.status(400).json({ message: "Invalid username or password" });
        }

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Invalid username or password" });
        }

        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.json({
            message: "Login successful",
            token,
            username: user.username,
            role: user.role,
        });
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ message: "Login failed" });
    }
});

// Get Certificate of Registration by student_no
app.get("/certificate/:student_no", authenticateToken, async (req, res) => {
    const { student_no } = req.params;
    const { role } = req.user;

    if (role !== "admin" && role !== student_no) {
        return res.status(403).json({ message: "Forbidden: Access denied" });
    }

    try {
        const [results] = await db.promise().query("SELECT * FROM certificate_of_registration WHERE student_no = ?", [student_no]);
        if (results.length === 0) {
            return res.status(404).json({ message: "Certificate not found" });
        }

        const certificate = results[0];

        if (certificate.student_img) {
            certificate.student_img = certificate.student_img.toString('base64');
        }

        const multiValueFields = [
            'subject_code', 'subject_title', 'lec_units', 'lab_units',
            'credit_units', 'tuition_units', 'subject_section',
            'subject_schedule_room', 'subject_faculty'
        ];

        multiValueFields.forEach(field => {
            if (certificate[field] && typeof certificate[field] === 'string') {
                certificate[field] = certificate[field].split(',');
            }
        });

        res.json(certificate);
    } catch (error) {
        console.error("Database error:", error);
        res.status(500).json({ message: "Database error" });
    }
});

// Verify Certificate Access
app.get("/verify-certificate-access/:username/:student_no", authenticateToken, async (req, res) => {
    const { username, student_no } = req.params;
    const { role } = req.user;

    try {
        const [results] = await db.promise().query("SELECT role FROM users WHERE username = ?", [username]);
        if (results.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        const userRole = results[0].role;
        const hasAccess = userRole === student_no; // Admin access removed since admin page has no functionality
        //const hasAccess = userRole === "admin" || userRole === student_no;  // Original code with admin access

        res.json({
            hasAccess,
            message: hasAccess ? "Access granted" : "Access denied"
        });
    } catch (error) {
        console.error("Database error:", error);
        res.status(500).json({ message: "Database error" });
    }
});

app.listen(5000, () => {
    console.log("Server is running on Port 5000");
});