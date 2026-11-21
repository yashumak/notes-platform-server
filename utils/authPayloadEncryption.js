import {
  constants,
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  privateDecrypt,
} from "node:crypto";
import { getAppSecrets } from "../config/secrets.js";

const MAX_AUTH_PAYLOAD_BYTES = 64 * 1024;
let keyPair;

const getKeyPair = () => {
  if (keyPair) return keyPair;

  const configuredPrivateKey = getAppSecrets().authEncryptionPrivateKey?.replace(/\\n/g, "\n");
  if (configuredPrivateKey) {
    const privateKey = createPrivateKey(configuredPrivateKey);
    const publicKey = createPublicKey(privateKey);
    if (
      publicKey.asymmetricKeyType !== "rsa" ||
      (publicKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048
    ) {
      throw new Error("AUTH_ENCRYPTION_PRIVATE_KEY must be an RSA key of at least 2048 bits");
    }
    keyPair = {
      privateKey,
      publicKey: publicKey.export({ type: "spki", format: "pem" }).toString(),
    };
  } else if (process.env.NODE_ENV === "production") {
    throw new Error("AUTH_ENCRYPTION_PRIVATE_KEY must be configured in production");
  } else {
    const generated = generateKeyPairSync("rsa", {
      modulusLength: 3072,
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    keyPair = {
      privateKey: createPrivateKey(generated.privateKey),
      publicKey: generated.publicKey,
    };
  }

  return keyPair;
};

export const initializeAuthPayloadEncryption = () => {
  getKeyPair();
};

export const getAuthPayloadPublicKey = () => getKeyPair().publicKey;

const decodeBase64 = (value) => {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new Error("Invalid encrypted payload encoding");
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value) {
    throw new Error("Invalid encrypted payload encoding");
  }
  return decoded;
};

export const decryptAuthPayload = (req, res, next) => {
  try {
    const body = req.body;
    if (
      !body ||
      typeof body !== "object" ||
      Array.isArray(body) ||
      Object.keys(body).length !== 3 ||
      !("encryptedKey" in body) ||
      !("iv" in body) ||
      !("encryptedData" in body)
    ) {
      return res.status(400).json({ message: "Encrypted request payload is invalid" });
    }

    const { encryptedKey, iv, encryptedData } = body;
    const wrappedKey = decodeBase64(encryptedKey);
    const initializationVector = decodeBase64(iv);
    const encryptedBytes = decodeBase64(encryptedData);

    if (
      wrappedKey.length < 256 ||
      wrappedKey.length > 1024 ||
      initializationVector.length !== 12 ||
      encryptedBytes.length < 17 ||
      encryptedBytes.length > MAX_AUTH_PAYLOAD_BYTES
    ) {
      return res.status(400).json({ message: "Encrypted request payload is invalid" });
    }

    const aesKey = privateDecrypt(
      {
        key: getKeyPair().privateKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      wrappedKey
    );
    if (aesKey.length !== 32) {
      return res.status(400).json({ message: "Encrypted request payload is invalid" });
    }

    const decipher = createDecipheriv("aes-256-gcm", aesKey, initializationVector);
    const authenticationTag = encryptedBytes.subarray(encryptedBytes.length - 16);
    decipher.setAuthTag(authenticationTag);
    const plaintext = Buffer.concat([
      decipher.update(encryptedBytes.subarray(0, encryptedBytes.length - 16)),
      decipher.final(),
    ]);
    const payload = JSON.parse(plaintext.toString("utf8"));
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      return res.status(400).json({ message: "Encrypted request payload is invalid" });
    }

    req.body = payload;
    return next();
  } catch {
    return res.status(400).json({ message: "Encrypted request payload is invalid" });
  }
};
