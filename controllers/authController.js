const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const sendEmail = require("../utils/sendEmail");

// Generate 4 digit OTP
const generateOTP = () => Math.floor(10000 + Math.random() * 90000);

// ---------------------- SIGNUP ----------------------
exports.signup = async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    let user = await User.findOne({ email });
    if (user)
      return res.json({ success: false, message: "Email already exists" });

    const hashed = await bcrypt.hash(password, 10);

    user = await User.create({ name, email, role, password: hashed });

    res.json({ success: true, message: "Signup successful" });
  } catch (error) {
    res.json({ success: false, error });
  }
};

// ---------------------- LOGIN ----------------------
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.json({ success: false, message: "Invalid email" });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.json({ success: false, message: "Invalid password" });

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ success: true, token });
  } catch (error) {
    res.json({ success: false, error });
  }
};

// ---------------------- PROFILE ----------------------
exports.profile = async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    res.json({ success: true, user });
  } catch (error) {
    res.json({ success: false, error });
  }
};

// ---------------------- SEND OTP ----------------------
exports.sendOTP = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user)
      return res.json({
        success: false,
        message: "No account found with this email",
      });

    const otp = generateOTP();

    user.otp = otp;
    user.otpExpire = Date.now() + 10 * 60 * 1000; // 10 min
    await user.save();

    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Password Reset OTP</title>
  <style>
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background-color: #f4f6f8;
      margin: 0;
      padding: 0;
    }
    .container {
      max-width: 500px;
      margin: 50px auto;
      background-color: #ffffff;
      padding: 30px;
      border-radius: 8px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
      text-align: center;
    }
    h2 {
      color: #333333;
    }
    p {
      color: #555555;
      font-size: 16px;
    }
    .otp {
      display: inline-block;
      font-size: 32px;
      font-weight: bold;
      letter-spacing: 8px;
      color: #1a73e8;
      margin: 20px 0;
      padding: 15px 25px;
      border: 2px dashed #1a73e8;
      border-radius: 6px;
    }
    .footer {
      margin-top: 30px;
      font-size: 14px;
      color: #999999;
    }
    .btn {
      display: inline-block;
      margin-top: 20px;
      background-color: #1a73e8;
      color: white;
      text-decoration: none;
      padding: 12px 25px;
      border-radius: 5px;
      font-weight: bold;
    }
  </style>
</head>
<body>
  <div class="container">
    <h2>Password Reset Request</h2>
    <p>Hello,</p>
    <p>We received a request to reset your password. Use the OTP below to securely reset it. If you did not request this, please ignore this email.</p>
    
    <div class="otp">${otp}</div>
    
    <p>This OTP will expire in <strong>10 minutes</strong>.</p>
    
    <a href="#" class="btn">Reset Password</a>
    
    <div class="footer">
      &copy; ${new Date().getFullYear()} Your Company Name. All rights reserved.
    </div>
  </div>
</body>
</html>
`;

    await sendEmail(email, "Password Reset OTP", html);

    res.json({ success: true, message: "OTP sent to your email" });
  } catch (error) {
    res.json({ success: false, error });
  }
};

// ---------------------- VERIFY OTP & RESET PASSWORD ----------------------
exports.resetPassword = async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    const user = await User.findOne({ email });

    if (!user) return res.json({ success: false, message: "Invalid email" });
    if (user.otp !== otp)
      return res.json({ success: false, message: "Wrong OTP" });
    if (user.otpExpire < Date.now())
      return res.json({ success: false, message: "OTP expired" });

    const hashed = await bcrypt.hash(newPassword, 10);

    user.password = hashed;
    user.otp = undefined;
    user.otpExpire = undefined;
    await user.save();

    res.json({ success: true, message: "Password updated successfully" });
  } catch (error) {
    res.json({ success: false, error });
  }
};
