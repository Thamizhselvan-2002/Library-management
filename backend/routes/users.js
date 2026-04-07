const express = require("express");
const User = require("../models/User");
const Transaction = require("../models/Transaction");
const { auth, adminOnly } = require("../middleware/auth");
const { generateOTP, otpExpiry, isExpired } = require("../utils/otp");
const { sendMail, registrationOTPTemplate } = require("../utils/mailer");
const jwt = require("jsonwebtoken");

const router = express.Router();

// ── GET /api/users — admin: list all students
router.get("/", auth, adminOnly, async (req, res) => {
  try {
    const users = await User.find({ role: "student" }).select("-password").sort("-createdAt");
    res.json(users);
  } catch (err) { res.status(500).json({ message: "Failed to fetch users" }); }
});

// ── GET /api/users/stats/overview — admin dashboard
router.get("/stats/overview", auth, adminOnly, async (req, res) => {
  try {
    const totalStudents = await User.countDocuments({ role: "student", isActive: true });
    const totalActive = await Transaction.countDocuments({ status: { $in: ["active", "overdue"] }, type: "borrow" });
    const totalOverdue = await Transaction.countDocuments({ status: "overdue" });
    const totalReserved = await Transaction.countDocuments({ status: "reserved" });
    const fineResult = await Transaction.aggregate([{ $group: { _id: null, total: { $sum: "$fineAmount" } } }]);
    const unpaidFines = await Transaction.aggregate([{ $match: { fineAmount: { $gt: 0 }, finePaid: false } }, { $group: { _id: null, total: { $sum: "$fineAmount" } } }]);
    res.json({ totalStudents, totalActive, totalOverdue, totalReserved, totalFines: fineResult[0]?.total || 0, unpaidFines: unpaidFines[0]?.total || 0 });
  } catch (err) { res.status(500).json({ message: "Failed to fetch stats" }); }
});

// ── GET /api/users/:id — admin or own profile
router.get("/:id", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin" && req.user._id.toString() !== req.params.id) return res.status(403).json({ message: "Not authorized" });
    const user = await User.findById(req.params.id).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json(user);
  } catch (err) { res.status(500).json({ message: "Failed to fetch user" }); }
});

// ── PUT /api/users/:id — update profile (name, phone, studentId, profileImage)
router.put("/:id", auth, async (req, res) => {
  try {
    if (req.user._id.toString() !== req.params.id && req.user.role !== "admin") return res.status(403).json({ message: "Not authorized" });
    const { name, phone, studentId, profileImage } = req.body;
    const updates = {};
    if (name) updates.name = name.trim();
    if (phone) {
      const phoneClean = phone.replace(/\s/g, "");
      if (!/^\d{10}$/.test(phoneClean)) return res.status(400).json({ message: "Phone must be 10 digits" });
      updates.phone = phoneClean;
    }
    if (studentId !== undefined) updates.studentId = studentId.trim();
    if (profileImage !== undefined) updates.profileImage = profileImage;

    const user = await User.findByIdAndUpdate(req.params.id, updates, { new: true }).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json(user.toSafeObject ? user.toSafeObject() : user);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── POST /api/users/:id/change-email/send-otp — send OTP to NEW email
router.post("/:id/change-email/send-otp", auth, async (req, res) => {
  try {
    if (req.user._id.toString() !== req.params.id) return res.status(403).json({ message: "Not authorized" });
    const { newEmail } = req.body;
    if (!newEmail) return res.status(400).json({ message: "New email is required" });
    const emailRegex = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(newEmail.trim())) return res.status(400).json({ message: "Invalid email format" });
    const normalizedNew = newEmail.toLowerCase().trim();
    const existing = await User.findOne({ email: normalizedNew });
    if (existing) return res.status(409).json({ message: "This email is already in use" });

    const otp = generateOTP();
    const user = await User.findById(req.params.id);
    user.newEmailPending = normalizedNew;
    user.emailChangeOtp = otp;
    user.emailChangeExpiry = otpExpiry(10);
    await user.save({ validateBeforeSave: false });

    await sendMail(normalizedNew, "📚 Libraria — Verify your new email", registrationOTPTemplate(user.name, otp));
    res.json({ message: `OTP sent to ${normalizedNew}`, expiresIn: 600 });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── POST /api/users/:id/change-email/verify-otp — verify and apply new email
router.post("/:id/change-email/verify-otp", auth, async (req, res) => {
  try {
    if (req.user._id.toString() !== req.params.id) return res.status(403).json({ message: "Not authorized" });
    const { otp } = req.body;
    const user = await User.findById(req.params.id);
    if (!user || !user.emailChangeOtp) return res.status(400).json({ message: "No email change request found" });
    if (isExpired(user.emailChangeExpiry)) return res.status(400).json({ message: "OTP expired. Please request again." });
    if (user.emailChangeOtp !== otp.trim()) return res.status(400).json({ message: "Incorrect OTP" });

    user.email = user.newEmailPending;
    user.newEmailPending = null; user.emailChangeOtp = null; user.emailChangeExpiry = null;
    await user.save({ validateBeforeSave: false });

    // Issue fresh token with updated email
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || "fallback_secret", { expiresIn: "7d" });
    res.json({ message: "Email updated successfully.", token, user: user.toSafeObject() });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── PUT /api/users/:id/change-password — change password (authenticated)
router.put("/:id/change-password", auth, async (req, res) => {
  try {
    if (req.user._id.toString() !== req.params.id) return res.status(403).json({ message: "Not authorized" });
    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: "User not found" });
    const match = await user.comparePassword(currentPassword);
    if (!match) return res.status(400).json({ message: "Current password is incorrect" });
    const pwRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,}$/;
    if (!pwRegex.test(newPassword)) return res.status(400).json({ message: "New password must be 8+ chars with uppercase, lowercase, number and special character" });
    user.password = newPassword;
    await user.save();
    res.json({ message: "Password changed successfully." });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── PUT /api/users/:id/deactivate — admin only
router.put("/:id/deactivate", auth, adminOnly, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(req.params.id, { isActive: false }, { new: true }).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json(user);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

module.exports = router;
