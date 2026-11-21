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

const authEncryptionKeyError = (code, message) => {
  const error = new Error(message);
  error.code = code;
  return error;
};

const normalizePrivateKey = (value) => {
  let key = value.trim().replace(/^\uFEFF/, "");
  if (key.startsWith('"') && key.endsWith('"')) {
    try {
      const decoded = JSON.parse(key);
      if (typeof decoded === "string") key = decoded;
    } catch {
      // Keep the original value so validation reports the malformed PEM.
    }
  }
  return key
    .replace(/\\r\\n/g, "\n")
    .replace(/\\n/g, "\n")
    .replace(/\r\n?/g, "\n");
};

const getKeyPair = () => {
  if (keyPair) return keyPair;

  const rawPrivateKey = getAppSecrets().authEncryptionPrivateKey;
  const configuredPrivateKey = rawPrivateKey
    ? normalizePrivateKey(rawPrivateKey)
    : undefined;
  if (configuredPrivateKey) {
    let privateKey;
    let publicKey;
    try {
      privateKey = createPrivateKey(configuredPrivateKey);
      publicKey = createPublicKey(privateKey);
    } catch (cause) {
      const error = authEncryptionKeyError(
        "AUTH_ENCRYPTION_KEY_INVALID_FORMAT",
        "AUTH_ENCRYPTION_PRIVATE_KEY must be an unencrypted PEM private key"
      );
      const pem = configuredPrivateKey.match(
        /-----BEGIN ([A-Z ]*PRIVATE KEY)-----([\s\S]*?)-----END ([A-Z ]*PRIVATE KEY)-----/
      );
      const encodedBody = pem?.[2].replace(/\s/g, "");
      error.diagnostics = {
        parserCode: /^ERR_[A-Z0-9_]+$/.test(cause?.code || "") ? cause.code : "UNKNOWN",
        hasPrivateKeyHeader: /^-----BEGIN (?:RSA )?PRIVATE KEY-----/.test(configuredPrivateKey),
        hasPrivateKeyFooter: /-----END (?:RSA )?PRIVATE KEY-----\s*$/.test(configuredPrivateKey),
        matchingPemLabels: Boolean(pem && pem[1] === pem[3]),
        bodyLooksBase64: Boolean(
          encodedBody &&
          encodedBody.length % 4 === 0 &&
          /^[A-Za-z0-9+/]+={0,2}$/.test(encodedBody)
        ),
      };
      throw error;
    }
    if (publicKey.asymmetricKeyType !== "rsa") {
      throw authEncryptionKeyError(
        "AUTH_ENCRYPTION_KEY_NOT_RSA",
        "AUTH_ENCRYPTION_PRIVATE_KEY must be an RSA key"
      );
    }
    if ((publicKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
      throw authEncryptionKeyError(
        "AUTH_ENCRYPTION_KEY_TOO_WEAK",
        "AUTH_ENCRYPTION_PRIVATE_KEY must be at least 2048 bits"
      );
    }
    keyPair = {
      privateKey,
      publicKey: publicKey.export({ type: "spki", format: "pem" }).toString(),
    };
  } else if (process.env.NODE_ENV === "production") {
    throw authEncryptionKeyError(
      "AUTH_ENCRYPTION_KEY_MISSING",
      "AUTH_ENCRYPTION_PRIVATE_KEY must be configured in production"
    );
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
