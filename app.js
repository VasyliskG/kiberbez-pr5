const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");

const bcrypt = require("bcryptjs");
const express = require("express");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const session = require("express-session");
const { requireAuth, requireRole } = require("./middleware/auth");
const { csrfToken, verifyCsrf } = require("./middleware/csrf");

const app = express();
const PORT = process.env.PORT || 3000;
const usersFile = path.join(__dirname, "data", "users.json");

app.set("view engine", "ejs");
app.use(helmet());
app.use(express.urlencoded({ extended: false, limit: "10kb" }));
app.use(express.json({ limit: "10kb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use(
    session({
        secret: process.env.SESSION_SECRET || "dev-secret-change-me",
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            sameSite: "lax",
            secure: process.env.NODE_ENV === "production"
        }
    })
);
app.use(csrfToken);
app.use(verifyCsrf);

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: "Забагато спроб входу. Спробуйте пізніше."
});

async function readUsers() {
    const data = await fs.readFile(usersFile, "utf8");
    return JSON.parse(data);
}

async function writeUsers(users) {
    await fs.writeFile(usersFile, JSON.stringify(users, null, 2) + "\n", "utf8");
}

function validateCredentials(username, password) {
    if (typeof username !== "string" || typeof password !== "string") {
        return "Некоректні дані форми.";
    }
    if (!username.trim() || username.length < 3 || username.length > 30) {
        return "Username повинен містити від 3 до 30 символів.";
    }
    if (/[\u0000-\u001F\u007F]/.test(username)) {
        return "Username містить недопустимі символи.";
    }
    if (password.length < 8 || password.length > 72) {
        return "Пароль повинен містити від 8 до 72 символів.";
    }
    return null;
}

function renderRegisterError(res, status, error) {
    return res.status(status).render("register", { error });
}

function renderLoginError(res, status, error) {
    return res.status(status).render("login", { error });
}

app.get("/", (req, res) => {
    res.render("home", { user: req.session.user || null });
});

app.get("/register", (req, res) => {
    res.render("register", { error: null });
});

app.post("/register", async (req, res, next) => {
    try {
        const { username, password } = req.body;
        const validationError = validateCredentials(username, password);
        if (validationError) {
            return renderRegisterError(res, 400, validationError);
        }

        const normalizedUsername = username.trim();
        const users = await readUsers();
        const exists = users.some(
            (user) => user.username.toLowerCase() === normalizedUsername.toLowerCase()
        );
        if (exists) {
            return renderRegisterError(res, 409, "Користувач уже існує");
        }

        const passwordHash = await bcrypt.hash(password, 12);
        users.push({
            id: crypto.randomUUID(),
            username: normalizedUsername,
            passwordHash,
            role: "USER"
        });
        await writeUsers(users);
        return res.redirect("/login");
    } catch (error) {
        return next(error);
    }
});

app.get("/login", (req, res) => {
    res.render("login", { error: null });
});

app.post("/login", loginLimiter, async (req, res, next) => {
    try {
        const { username, password } = req.body;
        const validationError = validateCredentials(username, password);
        if (validationError) {
            return renderLoginError(res, 400, validationError);
        }

        const users = await readUsers();
        const user = users.find(
            (item) => item.username.toLowerCase() === username.trim().toLowerCase()
        );
        if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
            return renderLoginError(res, 401, "Невірне ім'я користувача або пароль");
        }

        req.session.regenerate((error) => {
            if (error) {
                return next(error);
            }
            req.session.csrfToken = crypto.randomBytes(32).toString("hex");
            req.session.user = {
                id: user.id,
                username: user.username,
                role: user.role,
                lastLogin: new Date().toISOString()
            };
            return res.redirect("/home");
        });
    } catch (error) {
        return next(error);
    }
});

app.get("/home", requireAuth, (req, res) => {
    res.render("home", { user: req.session.user });
});

app.get("/profile", requireAuth, (req, res) => {
    res.render("profile", { user: req.session.user });
});

app.get("/admin", requireRole("ADMIN"), async (req, res, next) => {
    try {
        const users = await readUsers();
        res.render("admin", { user: req.session.user, users });
    } catch (error) {
        next(error);
    }
});

app.post("/logout", (req, res, next) => {
    req.session.destroy((error) => {
        if (error) {
            return next(error);
        }
        return res.redirect("/login");
    });
});

app.use((req, res) => {
    res.status(404).render("404", { message: "Сторінку не знайдено." });
});

app.use((error, req, res, next) => {
    console.error(error);
    if (res.headersSent) {
        return next(error);
    }
    const status = Number.isInteger(error.status) && error.status >= 400
        ? error.status
        : 500;
    if (status === 413) {
        return res.status(413).render("403", {
            message: "Запит перевищує дозволений розмір."
        });
    }
    return res.status(status).render("500", {
        message: "Сталася внутрішня помилка сервера."
    });
});

if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`Сервер запущено: http://localhost:${PORT}`);
    });
}

module.exports = { app, readUsers, writeUsers, validateCredentials };
