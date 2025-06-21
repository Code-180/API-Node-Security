//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// === Required Packages ===
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
import xss from "xss";
import { z } from "zod";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import morgan from "morgan";
import express from "express";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import mongoSanitize from "express-mongo-sanitize";
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// === Load Environment Variables ===
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
dotenv.config();
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// APP INIT
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
const app = express();
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// === Middlewares Setup ===
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Helmet - Add secure HTTP headers
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
app.use(helmet());
// app.use(helmet({
//     contentSecurityPolicy: {
//         directives: {
//             "script-src": ["'self'", "yourdomain.com"],
//         },
//     },
// }));
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// CORS - Restrict who can access your API
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
app.use(cors({
    origin: ['https://yourdomain.com'],
    methods: ['GET', 'POST', 'PUT', 'DELETE']
}));
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Rate Limit - Prevent abuse
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 min
    max: 100, // limit each IP to 100 requests
});
app.use(limiter);
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Body Parser with Payload Limit
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
app.use(express.json({ limit: '10kb' }));
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Sanitize inputs against NoSQL injection
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
app.use(mongoSanitize());
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Logging - Track requests
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
app.use(morgan('combined'));
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
//<FUNCTION>
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// JWT Verification Middleware
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
const verifyToken = (req, res, next) => {
    const token = req.headers["x-auth"];
    if (!token) return res.status(401).send("Access denied");
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).send("Invalid token");
    }
};
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Role-based middleware
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
const isAdmin = (req, res, next) => {
    // Simulate role from token payload
    const userRole = req.user.role || "user"; // default to 'user'
    if (userRole !== "admin") return res.status(403).send("Admins only");
    next();
};
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// <MAIN>
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// === Input Validation using Zod ===
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
const loginSchema = z.object({
    email: z.string().email(),
    password: z.string().min(6)
});
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// === API Routes ===
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Validate and sanitize inputs
app.post("/api/login", (req, res) => {
    const result = loginSchema.safeParse(req.body);
    if (!result.success) {
        return res.status(400).json({ error: "Invalid input" });
    }
    //++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // XSS protection
    //++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    const cleanEmail = xss(req.body.email);
    const cleanPassword = xss(req.body.password);
    //++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Create token (JWT)
    //++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    const token = jwt.sign({ email: cleanEmail }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: "Logged in", token });
});
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Protected route with auth + role check
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
app.get("/api/admin", verifyToken, isAdmin, (req, res) => {
    res.send("Welcome, admin!");
});
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// === Fallback Error Handler ===
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
app.use((err, req, res, next) => {
    console.error("Internal Error:", err.message);
    res.status(500).send("Something went wrong");
});
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// === Server Startup ===
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
const PORT = process.env.PORT || 5000;
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
app.listen(PORT, () => {
    console.log(`🚀 Server is running on port ${PORT}`);
});