const express = require("express");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const { auth } = require("../middleware/auth");
const { generateOTP, otpExpiry, isExpired } = require("../utils/otp");
const { sendMail, registrationOTPTemplate } = require("../utils/mailer");

const router = express.Router();
const signToken = (id) => jwt.sign({ id }, process.env.JWT_SECRET || "fallback_secret", { expiresIn: "7d" });

// ── Password strength validator
function validatePassword(password) {
  if (!password || password.length < 8) return "Password must be at least 8 characters";
  if (!/[A-Z]/.test(password)) return "Password must contain at least one uppercase letter";
  if (!/[a-z]/.test(password)) return "Password must contain at least one lowercase letter";
  if (!/[0-9]/.test(password)) return "Password must contain at least one number";
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) return "Password must contain at least one special character (!@#$%^&* etc.)";
  return null;
}

// ════════════════════════════════════════════════
// REGISTER — Step 1: validate + send OTP
// ════════════════════════════════════════════════
router.post("/register/send-otp", async (req, res) => {
  try {
    const { name, email, phone, password, role, studentId, adminSecret } = req.body;
    if (!name || !email || !phone || !password) return res.status(400).json({ message: "All fields are required" });

    const emailRegex = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(email.trim())) return res.status(400).json({ message: "Please enter a valid email address" });

    const phoneClean = phone.replace(/\s/g, "");
    if (!/^\d{10}$/.test(phoneClean)) return res.status(400).json({ message: "Phone must be a 10-digit number" });

    const pwError = validatePassword(password);
    if (pwError) return res.status(400).json({ message: pwError });

    const targetRole = role === "admin" ? "admin" : "student";
    if (targetRole === "admin") {
      const secret = process.env.ADMIN_SECRET || "ADMIN2024";
      if (adminSecret !== secret) return res.status(403).json({ message: "Invalid admin secret code" });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const existing = await User.findOne({ email: normalizedEmail });
    if (existing && existing.isEmailVerified) return res.status(409).json({ message: "Email already registered. Please login." });

    const otp = generateOTP();
    const expiry = otpExpiry(10);

    if (existing) {
      existing.name = name.trim(); existing.phone = phoneClean;
      existing.password = password; existing.role = targetRole;
      existing.studentId = studentId?.trim() || "";
      existing.emailOtp = otp; existing.emailOtpExpiry = expiry; existing.emailOtpAttempts = 0;
      await existing.save();
    } else {
      await User.create({
        name: name.trim(), email: normalizedEmail, phone: phoneClean, password,
        role: targetRole, studentId: studentId?.trim() || "",
        isEmailVerified: false, emailOtp: otp, emailOtpExpiry: expiry, emailOtpAttempts: 0,
      });
    }

    await sendMail(normalizedEmail, "📚 Libraria — Verify your email", registrationOTPTemplate(name.trim(), otp));
    res.json({ message: `OTP sent to ${normalizedEmail}`, email: normalizedEmail, expiresIn: 600 });
  } catch (err) {
    console.error("register/send-otp:", err.message);
    if (err.name === "ValidationError") return res.status(400).json({ message: Object.values(err.errors).map(e => e.message).join(", ") });
    if (err.code === 11000) return res.status(409).json({ message: "Email already registered. Please login." });
    res.status(500).json({ message: `Failed: ${err.message}` });
  }
});

// REGISTER — Step 2: verify OTP
router.post("/register/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ message: "Email and OTP required" });
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) return res.status(404).json({ message: "No registration found. Please start over." });
    if (user.isEmailVerified) return res.status(400).json({ message: "Already verified. Please login." });
    if (user.emailOtpAttempts >= 5) return res.status(429).json({ message: "Too many attempts. Request a new OTP." });
    if (isExpired(user.emailOtpExpiry)) return res.status(400).json({ message: "OTP expired. Request a new one." });
    if (user.emailOtp !== otp.trim()) {
      user.emailOtpAttempts += 1;
      await user.save({ validateBeforeSave: false });
      return res.status(400).json({ message: `Incorrect OTP. ${5 - user.emailOtpAttempts} attempts left.` });
    }
    user.isEmailVerified = true; user.emailOtp = null; user.emailOtpExpiry = null; user.emailOtpAttempts = 0;
    await user.save({ validateBeforeSave: false });
    res.json({ message: "Email verified! Registration complete.", token: signToken(user._id), user: user.toSafeObject() });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// REGISTER — Resend OTP
router.post("/register/resend-otp", async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email: email?.toLowerCase().trim() });
    if (!user || user.isEmailVerified) return res.status(400).json({ message: "Cannot resend OTP." });
    const otp = generateOTP();
    user.emailOtp = otp; user.emailOtpExpiry = otpExpiry(10); user.emailOtpAttempts = 0;
    await user.save({ validateBeforeSave: false });
    await sendMail(email, "📚 Libraria — New verification OTP", registrationOTPTemplate(user.name, otp));
    res.json({ message: "New OTP sent.", expiresIn: 600 });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ════════════════════════════════════════════════
// LOGIN — Direct (no OTP, email already verified)
// ════════════════════════════════════════════════
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Email and password required" });

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) return res.status(401).json({ message: "No account found with this email" });

    if (!user.isEmailVerified) {
      const otp = generateOTP();
      user.emailOtp = otp; user.emailOtpExpiry = otpExpiry(10); user.emailOtpAttempts = 0;
      await user.save({ validateBeforeSave: false });
      await sendMail(user.email, "📚 Libraria — Verify your email", registrationOTPTemplate(user.name, otp));
      return res.status(403).json({ message: "Email not verified. A verification OTP has been sent.", needsVerification: true, email: user.email });
    }

    const match = await user.comparePassword(password);
    if (!match) return res.status(401).json({ message: "Incorrect password" });
    if (!user.isActive) return res.status(403).json({ message: "Account deactivated" });

    console.log(`✅ Login: ${user.email}`);
    res.json({ token: signToken(user._id), user: user.toSafeObject() });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ════════════════════════════════════════════════
// FORGOT PASSWORD
// Step 1: send reset OTP to email
// ════════════════════════════════════════════════
router.post("/forgot-password/send-otp", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email is required" });
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    // Always respond OK to prevent email enumeration
    if (!user || !user.isEmailVerified) {
      return res.json({ message: "If that email exists, an OTP has been sent.", expiresIn: 600 });
    }
    const otp = generateOTP();
    user.resetOtp = otp; user.resetOtpExpiry = otpExpiry(10); user.resetOtpAttempts = 0;
    await user.save({ validateBeforeSave: false });

    const html = `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#0e0f13;font-family:'Segoe UI',Arial,sans-serif;">
    <div style="max-width:480px;margin:0 auto;padding:32px 16px;">
      <div style="background:#161820;border:1px solid #2e3040;border-radius:16px;overflow:hidden;">
        <div style="background:linear-gradient(135deg,#e8935a,#c96a30);padding:28px 32px;text-align:center;">
          <div style="font-size:28px;">🔑</div>
          <div style="font-size:22px;font-weight:800;color:#fff;">Reset Password</div>
          <div style="font-size:12px;color:rgba(255,255,255,0.7);margin-top:2px;">Libraria LMS</div>
        </div>
        <div style="padding:32px;">
          <p style="color:#9a96a0;font-size:14px;">Hi <strong style="color:#f0ede8;">${user.name}</strong>,</p>
          <p style="color:#9a96a0;font-size:14px;margin-bottom:24px;">Use this OTP to reset your password. It expires in <strong style="color:#e8935a;">10 minutes</strong>.</p>
          <div style="background:#1e2028;border:2px dashed #e8935a;border-radius:12px;padding:24px;text-align:center;margin-bottom:24px;">
            <div style="font-size:11px;color:#9a96a0;letter-spacing:0.12em;text-transform:uppercase;margin-bottom:10px;">Password reset code</div>
            <div style="font-size:42px;font-weight:800;letter-spacing:10px;color:#e8935a;font-family:'Courier New',monospace;">${otp}</div>
          </div>
          <p style="color:#e8665a;font-size:12px;">If you did not request a password reset, ignore this email.</p>
        </div>
      </div>
    </div></body></html>`;

    await sendMail(user.email, "🔑 Libraria — Reset your password", html);
    res.json({ message: "If that email exists, an OTP has been sent.", expiresIn: 600 });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// Step 2: verify reset OTP
router.post("/forgot-password/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ message: "Email and OTP required" });
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user || !user.resetOtp) return res.status(400).json({ message: "No reset request found. Please start over." });
    if (user.resetOtpAttempts >= 5) return res.status(429).json({ message: "Too many attempts. Request a new OTP." });
    if (isExpired(user.resetOtpExpiry)) return res.status(400).json({ message: "OTP expired. Request a new one." });
    if (user.resetOtp !== otp.trim()) {
      user.resetOtpAttempts += 1;
      await user.save({ validateBeforeSave: false });
      return res.status(400).json({ message: `Incorrect OTP. ${5 - user.resetOtpAttempts} attempts left.` });
    }
    // Issue a short-lived reset token
    const resetToken = jwt.sign({ id: user._id, purpose: "reset" }, process.env.JWT_SECRET || "fallback_secret", { expiresIn: "15m" });
    user.resetOtp = null; user.resetOtpExpiry = null; user.resetOtpAttempts = 0;
    await user.save({ validateBeforeSave: false });
    res.json({ message: "OTP verified. You may now set a new password.", resetToken });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// Step 3: set new password
router.post("/forgot-password/reset", async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;
    if (!resetToken || !newPassword) return res.status(400).json({ message: "Reset token and new password required" });
    const pwError = validatePassword(newPassword);
    if (pwError) return res.status(400).json({ message: pwError });
    let decoded;
    try { decoded = jwt.verify(resetToken, process.env.JWT_SECRET || "fallback_secret"); }
    catch { return res.status(400).json({ message: "Reset session expired. Please start over." }); }
    if (decoded.purpose !== "reset") return res.status(400).json({ message: "Invalid reset token." });
    const user = await User.findById(decoded.id);
    if (!user) return res.status(404).json({ message: "User not found." });
    user.password = newPassword;
    await user.save();
    res.json({ message: "Password reset successfully. You can now login." });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ════════════════════════════════════════════════
// GET /api/auth/me
// ════════════════════════════════════════════════
router.get("/me", auth, async (req, res) => {
  res.json({ user: req.user });
});

module.exports = router;
