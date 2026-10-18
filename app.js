const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");

const bcrypt = require("bcryptjs");
const express = require("express");
const session = require("express-session");
const { requireAuth, requireRole } = require("./middleware/auth");

const app = express();
const PORT = process.env.PORT || 3000;
const usersFile = path.join(__dirname, "data", "users.json");

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
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

async function readUsers() {
    const data = await fs.readFile(usersFile, "utf8");
    return JSON.parse(data);
}

async function writeUsers(users) {
    await fs.writeFile(usersFile, JSON.stringify(users, null, 2) + "\n", "utf8");
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
        const username = typeof req.body.username === "string" ? req.body.username.trim() : "";
        const password = typeof req.body.password === "string" ? req.body.password : "";

        if (!username || !password) {
            return renderRegisterError(res, 400, "Заповніть усі поля");
        }
        if (password.length < 8) {
            return renderRegisterError(res, 400, "Пароль має містити щонайменше 8 символів");
        }

        const users = await readUsers();
        const exists = users.some(
            (user) => user.username.toLowerCase() === username.toLowerCase()
        );
        if (exists) {
            return renderRegisterError(res, 409, "Користувач уже існує");
        }

        const passwordHash = await bcrypt.hash(password, 12);
        users.push({
            id: crypto.randomUUID(),
            username,
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

app.post("/login", async (req, res, next) => {
    try {
        const username = typeof req.body.username === "string" ? req.body.username.trim() : "";
        const password = typeof req.body.password === "string" ? req.body.password : "";
        const users = await readUsers();
        const user = users.find(
            (item) => item.username.toLowerCase() === username.toLowerCase()
        );

        if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
            return renderLoginError(res, 401, "Невірне ім'я користувача або пароль");
        }

        req.session.user = {
            id: user.id,
            username: user.username,
            role: user.role,
            lastLogin: new Date().toISOString()
        };
        return res.redirect("/home");
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

app.use((error, req, res, next) => {
    console.error(error);
    if (res.headersSent) {
        return next(error);
    }
    return res.status(500).send("Внутрішня помилка сервера");
});

if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`Сервер запущено: http://localhost:${PORT}`);
    });
}

module.exports = { app, readUsers, writeUsers };
