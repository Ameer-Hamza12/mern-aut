const express = require("express");
const router = express.Router();
const authController = require("../controllers/authController");
const { auth } = require("../middleware/authMiddleware");
const { authorizeRoles } = require("../middleware/roleMiddleware");

// Public
router.post("/signup", authController.signup);
router.post("/login", authController.login);
router.post("/send-otp", authController.sendOTP);
router.post("/reset-password", authController.resetPassword);

// User/Admin/Inspector → Profile
router.get("/profile",
    auth,
    authorizeRoles("admin"),
    authController.profile
);

// Admin only
router.get("/admin/users",
    auth,
    authorizeRoles("admin"),
    (req, res) => res.json({ success: true, message: "Admin: User list" })
);

// Admin + Inspector
router.get("/reports",
    auth,
    authorizeRoles("admin", "inspector"),
    (req, res) => res.json({ success: true, message: "Reports visible" })
);

// All roles
router.get("/dashboard",
    auth,
    authorizeRoles("user", "admin", "inspector"),
    (req, res) => res.json({
        success: true,
        message: `Dashboard for ${req.userRole}`
    })
);

module.exports = router;
