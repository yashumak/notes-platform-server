import mongoose from "mongoose";
import { logError, logInfo } from "../utils/logger.js";

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      ...(process.env.NODE_ENV === "production" ? { tls: true } : {}),
    });

    logInfo("database.connected");
  } catch (error) {
    logError("database.connection_failed");
    process.exit(1);
  }
};

export default connectDB;
