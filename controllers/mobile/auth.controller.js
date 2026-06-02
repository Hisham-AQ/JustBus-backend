const db = require("../../config/db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const { validationResult } = require("express-validator");


// ================= changePassword =================
const changePassword = async (req, res) => {
  try {
    const userId = req.user.id;
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: "Missing fields" });
    }


    const passwordRegex =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;

if (!passwordRegex.test(newPassword)) {
  return res.status(400).json({
    message:
      "Password must be at least 8 characters and contain uppercase, lowercase, and a number"
  });
}

    const [rows] = await db.query(
      "SELECT password FROM users WHERE id = ?",
      [userId]
    );

    const isValid = await bcrypt.compare(
      currentPassword,
      rows[0].password
    );

    if (!isValid) {
      return res.status(401).json({
        message: "Current password is incorrect",
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await db.query(
      "UPDATE users SET password = ? WHERE id = ?",
      [hashedPassword, userId]
    );

    res.json({ message: "Password updated successfully" });

  } catch (err) {
    console.error("CHANGE PASSWORD ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};



// ================= forgotPassword =================
const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    const [rows] = await db.query(
      "SELECT id FROM users WHERE email = ?",
      [email]
    );

    if (rows.length === 0) {
      return res.json({
        message: "If this email exists, a reset code has been sent",
      });
    }

    const userId = rows[0].id;

    const resetCode = Math.floor(
      100000 + Math.random() * 900000
    ).toString();

    const expires = new Date(Date.now() + 15 * 60 * 1000);

    await db.query(
      "UPDATE users SET reset_code = ?, reset_code_expires = ? WHERE id = ?",
      [resetCode, expires, userId]
    );

    await axios.post(
      "https://api.brevo.com/v3/smtp/email",
      {
        sender: {
          email: "smashni02@gmail.com",
          name: "JustBus Support",
        },
        to: [{ email }],
        subject: "JustBus Password Reset Code",
        htmlContent: `
          <p>You requested a password reset.</p>
          <h2>${resetCode}</h2>
          <p>This code expires in 15 minutes.</p>
        `,
      },
      {
        headers: {
          "api-key": process.env.BREVO_API_KEY,
          "Content-Type": "application/json",
        },
      }
    );

    res.json({ message: "A reset code has been sent" });

  } catch (err) {
    console.error("FORGOT PASSWORD ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};


// ================= resetPassword =================
const resetPassword = async (req, res) => {
  try {
    const { code, newPassword } = req.body;

    if (!code || !newPassword) {
      return res.status(400).json({
        message: "All fields are required",
      });
    }

    const [rows] = await db.query(
      `SELECT id, reset_code_expires
       FROM users WHERE reset_code = ?`,
      [code]
    );

    if (rows.length === 0) {
      return res.status(400).json({
        message: "Invalid reset code",
      });
    }

    const user = rows[0];

    if (
      !user.reset_code_expires ||
      new Date(user.reset_code_expires) < new Date()
    ) {
      return res.status(400).json({
        message: "Reset code expired",
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await db.query(
      `UPDATE users
       SET password = ?, reset_code = NULL, reset_code_expires = NULL
       WHERE id = ?`,
      [hashedPassword, user.id]
    );

    res.json({ message: "Password reset successfully" });

  } catch (err) {
    console.error("RESET PASSWORD ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};



// ================= register =================
const register = async (req, res) => {

  const errors = validationResult(req);

if (!errors.isEmpty()) {
  return res.status(400).json({
    errors: errors.array()
  });
}

  try {
    const { name, email, password, phone, gender, birth_date } = req.body;

    const role = "student";

    if (!name || !email || !password || !role || !phone) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    if (!/^\d{9,15}$/.test(phone)) {
      return res.status(400).json({ message: "Invalid phone number" });
    }

    const [existing] = await db.execute(
      "SELECT id FROM users WHERE email = ?",
      [email]
    );

    if (existing.length > 0) {
      return res.status(409).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await db.execute(
      `INSERT INTO users 
       (name, email, password, role, phone, gender, birth_date)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        name,
        email,
        hashedPassword,
        role,
        phone || null,
        gender || null,
        birth_date || null,
      ]
    );

    res.status(201).json({ message: "User registered successfully" });

  } catch (err) {
    console.error("REGISTER ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};


// ================= login =================
const login = async (req, res) => {

    const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({
      errors: errors.array()
    });
  }

  try {
    const { email, password, role } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required",
      });
    }

    const [rows] = await db.execute(
  `
  SELECT
    id,
    email,
    password,
    role,
    is_blacklisted,
    blacklist_reason,
    blacklist_until,
    failed_login_attempts,
    locked_until
  FROM users
  WHERE email = ?
  AND role = ?
  `,
  [email, role]
);

    if (rows.length === 0) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = rows[0];

    if (
  user.locked_until &&
  new Date(user.locked_until) < new Date()
) {
  await db.execute(
    `
    UPDATE users
    SET
      failed_login_attempts = 0,
      locked_until = NULL
    WHERE id = ?
    `,
    [user.id]
  );

  user.failed_login_attempts = 0;
  user.locked_until = null;
}

    if (
  user.locked_until &&
  new Date(user.locked_until) > new Date()
) {
  return res.status(423).json({
    message: `Account locked until ${user.locked_until}`
  });
}

if (
  user.is_blacklisted &&
  user.blacklist_until &&
  new Date(user.blacklist_until) < new Date()
) {

  await db.execute(
    `
    UPDATE users
    SET
      is_blacklisted = FALSE,
      blacklist_reason = NULL,
      blacklist_until = NULL
    WHERE id = ?
    `,
    [user.id]
  );

  user.is_blacklisted = false;
}

    const isValid = await bcrypt.compare(
  password,
  user.password
);

if (!isValid) {

  const attempts = user.failed_login_attempts + 1;

  if (attempts >= 5) {

    const lockedUntil = new Date(
      Date.now() + 15 * 60 * 1000
    );

    await db.execute(
      `
      UPDATE users
      SET
        failed_login_attempts = ?,
        locked_until = ?
      WHERE id = ?
      `,
      [attempts, lockedUntil, user.id]
    );

    return res.status(423).json({
      message:
        "Account locked for 15 minutes due to multiple failed login attempts"
    });
  }

  await db.execute(
    `
    UPDATE users
    SET failed_login_attempts = ?
    WHERE id = ?
    `,
    [attempts, user.id]
  );

  return res.status(401).json({
    message: `Invalid credentials (${attempts}/5)`
  });
}

        if (user.is_blacklisted) {

  return res.status(403).json({

    message:
      user.blacklist_until
      ? `Blacklisted until ${user.blacklist_until}`
      : "Your account is blacklisted",

    reason: user.blacklist_reason
  });
}


await db.execute(
  `
  UPDATE users
  SET
    failed_login_attempts = 0,
    locked_until = NULL
  WHERE id = ?
  `,
  [user.id]
);

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role,
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    


    res.json({
      token,
      role: user.role,
    });

  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};


// ================= adminLogin =================
const adminLogin = async (req, res) => {

    const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({
      errors: errors.array()
    });
  }

  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required",
      });
    }

    const [rows] = await db.execute(
      "SELECT id, name, email, password, role, failed_login_attempts, locked_until FROM users WHERE email = ?",
      [email]
    );

    if (rows.length === 0) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = rows[0];

    if (
  user.locked_until &&
  new Date(user.locked_until) < new Date()
) {
  await db.execute(
    `
    UPDATE users
    SET
      failed_login_attempts = 0,
      locked_until = NULL
    WHERE id = ?
    `,
    [user.id]
  );

  user.failed_login_attempts = 0;
  user.locked_until = null;
}

if (
  user.locked_until &&
  new Date(user.locked_until) > new Date()
) {
  return res.status(423).json({
    message: `Account locked until ${user.locked_until}`
  });
}


const isValid = await bcrypt.compare(
  password,
  user.password
);

if (!isValid) {

  const attempts = user.failed_login_attempts + 1;

  if (attempts >= 5) {

    const lockedUntil = new Date(
      Date.now() + 15 * 60 * 1000
    );

    await db.execute(
      `
      UPDATE users
      SET
        failed_login_attempts = ?,
        locked_until = ?
      WHERE id = ?
      `,
      [attempts, lockedUntil, user.id]
    );

    return res.status(423).json({
      message:
        "Account locked for 15 minutes due to multiple failed login attempts"
    });
  }

  await db.execute(
    `
    UPDATE users
    SET failed_login_attempts = ?
    WHERE id = ?
    `,
    [attempts, user.id]
  );

  return res.status(401).json({
    message: `Invalid credentials (${attempts}/5)`
  });
}

    if (user.role !== 'admin') {
      return res.status(403).json({ message: "Admins only" });
    }

    await db.execute(
  `
  UPDATE users
  SET
    failed_login_attempts = 0,
    locked_until = NULL
  WHERE id = ?
  `,
  [user.id]
);

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role,
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.json({
      token,
      role: user.role,
      name: user.name
    });

  } catch (err) {
    console.error("ADMIN LOGIN ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};
module.exports = {
  register,
  login,
  adminLogin,
  changePassword,
  forgotPassword,
  resetPassword,
};