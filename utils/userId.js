import { randomInt } from "node:crypto";

const USER_ID_ATTEMPTS = 5;

export const generateUserId = () =>
  randomInt(1_000_000_000, 10_000_000_000).toString();

export const ensureUserId = async (user) => {
  if (typeof user.user_id === "string" && /^\d{10}$/.test(user.user_id)) {
    return user.user_id;
  }

  for (let attempt = 0; attempt < USER_ID_ATTEMPTS; attempt += 1) {
    user.user_id = generateUserId();
    try {
      await user.save();
      return user.user_id;
    } catch (error) {
      if (error.code !== 11000 || !error.keyPattern?.user_id) {
        throw error;
      }
    }
  }

  throw new Error("Could not generate a unique user ID");
};
