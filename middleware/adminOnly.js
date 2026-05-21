module.exports = (req, res, next) => {

  // check if user exists
  if (!req.user) {
    return res.status(401).json({
      message: "Unauthorized"
    });
  }

  // check admin role
  if (req.user.role !== "admin") {
    return res.status(403).json({
      message: "Admins only"
    });
  }

  // continue to route
  next();
};