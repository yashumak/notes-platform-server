export const requireHttps = (req, res, next) => {
  if (process.env.NODE_ENV === "production" && !req.secure) {
    return res.status(426).json({ message: "HTTPS is required" });
  }
  next();
};
