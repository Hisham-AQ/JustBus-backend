const jwt = require("jsonwebtoken");

module.exports = function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;

  // Expect: Authorization: Bearer TOKEN
  if (!authHeader) {
    return res.status(401).json({ message: "Access token missing" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Attach user info to request
    req.user = decoded;

    next(); // ✅ user is authenticated
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};
