const crypto = require("node:crypto");

function csrfToken(req, res, next) {
    if (!req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(32).toString("hex");
    }
    res.locals.csrfToken = req.session.csrfToken;
    return next();
}

function verifyCsrf(req, res, next) {
    if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) {
        const token = req.body?._csrf;
        if (!token || token !== req.session.csrfToken) {
            return res.status(403).render("403", {
                message: "Недійсний або відсутній CSRF-токен."
            });
        }
    }
    return next();
}

module.exports = { csrfToken, verifyCsrf };
