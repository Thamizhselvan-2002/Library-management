const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const userSchema = new mongoose.Schema(
  {
    name:             { type: String, required: [true, "Name is required"], trim: true },
    email:            { type: String, required: [true, "Email is required"], unique: true, lowercase: true, trim: true },
    phone:            { type: String, required: [true, "Phone is required"], trim: true },
    password:         { type: String, required: [true, "Password is required"], minlength: [6, "Password must be at least 6 characters"] },
    role:             { type: String, enum: ["student", "admin"], default: "student" },
    studentId:        { type: String, trim: true, default: "" },
    profileImage:     { type: String, default: "" }, // base64 or URL

    // Email verification (register only)
    isEmailVerified:  { type: Boolean, default: false },
    emailOtp:         { type: String, default: null },
    emailOtpExpiry:   { type: Date, default: null },
    emailOtpAttempts: { type: Number, default: 0 },

    // Forgot password OTP
    resetOtp:         { type: String, default: null },
    resetOtpExpiry:   { type: Date, default: null },
    resetOtpAttempts: { type: Number, default: 0 },

    // Email change OTP (profile edit)
    newEmailPending:     { type: String, default: null },
    emailChangeOtp:      { type: String, default: null },
    emailChangeExpiry:   { type: Date, default: null },

    totalFine:        { type: Number, default: 0 },
    finePaid:         { type: Number, default: 0 },
    isActive:         { type: Boolean, default: true },
  },
  { timestamps: true }
);

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  try {
    this.password = await bcrypt.hash(this.password, 12);
    next();
  } catch (err) { next(err); }
});

userSchema.methods.comparePassword = async function (candidate) {
  return bcrypt.compare(candidate, this.password);
};

userSchema.methods.toSafeObject = function () {
  const obj = this.toObject();
  delete obj.password;
  delete obj.emailOtp;
  delete obj.emailOtpExpiry;
  delete obj.resetOtp;
  delete obj.resetOtpExpiry;
  delete obj.emailChangeOtp;
  delete obj.emailChangeExpiry;
  return obj;
};

module.exports = mongoose.model("User", userSchema);
