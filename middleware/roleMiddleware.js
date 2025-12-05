exports.authorizeRoles = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.userRole)) {
            return res.status(403).json({
                success: false,
                message: "Access denied: insufficient permissions"
            });
        }
        next();
    };
};
