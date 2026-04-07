const nodemailer = require("nodemailer");

// Reset cached transporter on each call so env vars are always re-read
// (important on Render where vars may load after module init)
let _transporter = null;
let _lastUser = null;

function getTransporter() {
  const user = process.env.EMAIL_USER;
  const pass = process.env.EMAIL_PASS;

  if (!user || user.includes("your_") || !pass || pass.includes("your_")) {
    return null;
  }

  // Re-create if credentials changed
  if (_transporter && _lastUser === user) return _transporter;

  _lastUser = user;

  // Try TLS port 587 first (more reliable on Render than 465)
  _transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 587,
    secure: false,           // STARTTLS on 587
    auth: { user, pass },
    tls: {
      rejectUnauthorized: false,
      ciphers: "SSLv3",
    },
    connectionTimeout: 20000,
    greetingTimeout: 15000,
    socketTimeout: 30000,
    pool: false,
  });

  console.log("✉️  Mailer ready (STARTTLS/587):", user);
  return _transporter;
}

async function sendMail(to, subject, html) {
  const t = getTransporter();
  if (!t) {
    // Dev fallback — print OTP to console so it's still usable locally
    const otpMatch = html.match(/\b(\d{6})\b/);
    console.log("═══════════════════════════════════════");
    console.log(`📧 [MOCK EMAIL] To: ${to} | Subject: ${subject}`);
    if (otpMatch) console.log(`   ✅ OTP: ${otpMatch[1]}`);
    console.log("═══════════════════════════════════════");
    return { mock: true };
  }

  try {
    const info = await t.sendMail({
      from: `"Libraria 📚" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      html,
    });
    console.log(`✉️  Sent to ${to} — ${info.messageId}`);
    return info;
  } catch (err) {
    console.error(`❌ Email error (port 587):`, err.message);

    // Fallback: retry with port 465 SSL
    console.log("   Retrying with port 465...");
    try {
      const fallback = nodemailer.createTransport({
        host: "smtp.gmail.com",
        port: 465,
        secure: true,
        auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
        tls: { rejectUnauthorized: false },
        connectionTimeout: 20000,
        socketTimeout: 30000,
      });
      const info2 = await fallback.sendMail({
        from: `"Libraria 📚" <${process.env.EMAIL_USER}>`,
        to, subject, html,
      });
      console.log(`✉️  Sent via 465 to ${to}`);
      return info2;
    } catch (err2) {
      console.error(`❌ Email also failed on 465:`, err2.message);
      const otpMatch = html.match(/\b(\d{6})\b/);
      if (otpMatch) console.log(`   OTP (check logs): ${otpMatch[1]}`);
      throw new Error(
        `Email delivery failed. Please verify:\n` +
        `1. EMAIL_USER and EMAIL_PASS are set in Render Environment Variables\n` +
        `2. Gmail App Password (16 chars, no spaces) — NOT your regular Gmail password\n` +
        `3. 2-Step Verification is ON at myaccount.google.com/security\n` +
        `Original error: ${err.message}`
      );
    }
  }
}

function registrationOTPTemplate(name, otp) {
  return `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#0e0f13;font-family:'Segoe UI',Arial,sans-serif;">
  <div style="max-width:480px;margin:0 auto;padding:32px 16px;">
    <div style="background:#161820;border:1px solid #2e3040;border-radius:16px;overflow:hidden;">
      <div style="background:linear-gradient(135deg,#e8c878,#c9a84c);padding:28px 32px;text-align:center;">
        <div style="font-size:28px;margin-bottom:6px;">📚</div>
        <div style="font-size:22px;font-weight:800;color:#1a1400;">Libraria</div>
      </div>
      <div style="padding:32px;">
        <h2 style="color:#f0ede8;font-size:18px;margin:0 0 8px;">Verify your email</h2>
        <p style="color:#9a96a0;font-size:14px;margin:0 0 24px;">Hi <strong style="color:#f0ede8;">${name}</strong> — enter this code to complete registration:</p>
        <div style="background:#1e2028;border:2px dashed #e8c878;border-radius:12px;padding:24px;text-align:center;margin-bottom:24px;">
          <div style="font-size:11px;color:#9a96a0;letter-spacing:0.12em;text-transform:uppercase;margin-bottom:10px;">Verification code</div>
          <div style="font-size:42px;font-weight:800;letter-spacing:10px;color:#e8c878;font-family:'Courier New',monospace;">${otp}</div>
          <div style="font-size:12px;color:#6b6878;margin-top:10px;">Expires in <strong style="color:#e8935a;">10 minutes</strong></div>
        </div>
        <p style="color:#e8935a;font-size:12px;margin:0;">Never share this code. Libraria staff will never ask for it.</p>
      </div>
    </div>
  </div></body></html>`;
}

function loginOTPTemplate(name, otp) {
  return `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#0e0f13;font-family:'Segoe UI',Arial,sans-serif;">
  <div style="max-width:480px;margin:0 auto;padding:32px 16px;">
    <div style="background:#161820;border:1px solid #2e3040;border-radius:16px;overflow:hidden;">
      <div style="background:linear-gradient(135deg,#6ea3e8,#4a7bc8);padding:28px 32px;text-align:center;">
        <div style="font-size:28px;margin-bottom:6px;">🔐</div>
        <div style="font-size:22px;font-weight:800;color:#fff;">Sign-in Code</div>
      </div>
      <div style="padding:32px;">
        <p style="color:#9a96a0;font-size:14px;">Hi <strong style="color:#f0ede8;">${name}</strong>,</p>
        <div style="background:#1e2028;border:2px dashed #6ea3e8;border-radius:12px;padding:24px;text-align:center;margin:16px 0;">
          <div style="font-size:42px;font-weight:800;letter-spacing:10px;color:#6ea3e8;font-family:'Courier New',monospace;">${otp}</div>
          <div style="font-size:12px;color:#6b6878;margin-top:10px;">Expires in <strong style="color:#e8935a;">10 minutes</strong></div>
        </div>
      </div>
    </div>
  </div></body></html>`;
}

function dueReminderTemplate(name, bookTitle, author, isbn, dueDate) {
  return `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#0e0f13;font-family:'Segoe UI',Arial,sans-serif;">
  <div style="max-width:480px;margin:0 auto;padding:32px 16px;">
    <div style="background:#161820;border:1px solid #2e3040;border-radius:16px;overflow:hidden;">
      <div style="background:linear-gradient(135deg,#5ecc8b,#3a9e6a);padding:24px;text-align:center;">
        <div style="font-size:24px;">⏰</div><div style="font-size:18px;font-weight:800;color:#fff;">Return Reminder</div>
      </div>
      <div style="padding:28px;">
        <p style="color:#9a96a0;">Hi <strong style="color:#f0ede8;">${name}</strong>, your book is due <strong style="color:#e8c878;">tomorrow</strong>:</p>
        <div style="background:#1e2028;border-left:4px solid #e8c878;padding:16px;border-radius:0 8px 8px 0;margin:16px 0;">
          <div style="font-size:17px;font-weight:700;color:#f0ede8;">${bookTitle}</div>
          <div style="font-size:13px;color:#9a96a0;">by ${author}</div>
          ${isbn ? `<div style="font-size:11px;color:#6b6878;">ISBN: ${isbn}</div>` : ""}
        </div>
        <div style="background:#252730;border-radius:8px;padding:12px 16px;">Due: <strong style="color:#e8c878;">${dueDate}</strong></div>
        <p style="color:#e8935a;font-size:12px;margin-top:12px;">Late returns: ₹${process.env.FINE_PER_DAY || 5}/day fine.</p>
      </div>
    </div>
  </div></body></html>`;
}

function fineNoticeTemplate(name, bookTitle, overdueDays, fineAmount) {
  return `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#0e0f13;font-family:'Segoe UI',Arial,sans-serif;">
  <div style="max-width:480px;margin:0 auto;padding:32px 16px;">
    <div style="background:#161820;border:1px solid rgba(232,102,90,0.3);border-radius:16px;overflow:hidden;">
      <div style="background:linear-gradient(135deg,#e8665a,#b84a3e);padding:24px;text-align:center;">
        <div style="font-size:24px;">⚠️</div><div style="font-size:18px;font-weight:800;color:#fff;">Overdue Fine</div>
      </div>
      <div style="padding:28px;">
        <p style="color:#9a96a0;">Hi <strong style="color:#f0ede8;">${name}</strong>, <strong style="color:#f0ede8;">"${bookTitle}"</strong> is <strong style="color:#e8665a;">${overdueDays} day(s) overdue</strong>.</p>
        <div style="background:rgba(232,102,90,0.1);border-radius:8px;padding:16px;margin:16px 0;">
          <div style="display:flex;justify-content:space-between;margin-bottom:8px;"><span style="color:#9a96a0;">Days</span><strong style="color:#e8665a;">${overdueDays}</strong></div>
          <div style="display:flex;justify-content:space-between;margin-bottom:8px;"><span style="color:#9a96a0;">Rate</span><span>₹${process.env.FINE_PER_DAY || 5}/day</span></div>
          <div style="border-top:1px solid rgba(232,102,90,0.3);padding-top:8px;display:flex;justify-content:space-between;"><strong>Total Fine</strong><span style="color:#e8665a;font-size:20px;font-weight:800;">₹${fineAmount}</span></div>
        </div>
        <p style="color:#9a96a0;font-size:12px;">Return the book and pay at the library counter immediately.</p>
      </div>
    </div>
  </div></body></html>`;
}

module.exports = { sendMail, registrationOTPTemplate, loginOTPTemplate, dueReminderTemplate, fineNoticeTemplate };
