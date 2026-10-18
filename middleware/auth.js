function requireAuth(req, res, next) {
    if (!req.session.user) {
        return res.redirect("/login");
    }
    return next();
}

function requireRole(role) {
    return (req, res, next) => {
        if (!req.session.user) {
            return res.redirect("/login");
        }
        if (req.session.user.role !== role) {
            return res.status(403).render("403", {
                message: "У вас немає прав для перегляду цієї сторінки."
            });
        }
        return next();
    };
}

module.exports = { requireAuth, requireRole };
