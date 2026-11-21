import mongoose from "mongoose";
import { logError, logInfo } from "../utils/logger.js";
import { getAppSecrets } from "./secrets.js";

const connectDB = async () => {
  try {
    const { mongoUri } = getAppSecrets();
    await mongoose.connect(mongoUri, {
      ...(process.env.NODE_ENV === "production" ? { tls: true } : {}),
    });

    logInfo("database.connected");
  } catch (error) {
    logError("database.connection_failed");
    process.exit(1);
  }
};

export default connectDB;
