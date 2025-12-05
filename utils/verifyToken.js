const jwt = require("jsonwebtoken");

module.exports = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) return res.json({ success: false, message: "No token" });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.json({ success: false, message: "Invalid token" });

        req.userId = decoded.id;
        next();
    });
};
