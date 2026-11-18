// Configuration must be complete before any application module is imported:
// several modules read process.env at import time.
import dotenv from "dotenv";
import { loadRuntimeSecretsOrExit } from "./config/secrets.js";

dotenv.config();
await loadRuntimeSecretsOrExit();

await import("./server.js");
