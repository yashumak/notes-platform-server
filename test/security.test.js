import assert from "node:assert/strict";
import bcrypt from "bcryptjs";
import cookieParser from "cookie-parser";
import express from "express";
import { Readable } from "node:stream";
import {
  GetObjectCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import {
  constants,
  createCipheriv,
  publicEncrypt,
  randomBytes,
} from "node:crypto";
import test from "node:test";
import authRoutes from "../routes/auth.routes.js";
import notesRoutes from "../routes/notes.routes.js";
import adminRoutes from "../routes/admin.routes.js";
import {
  completeNoteUpload,
  createNoteUploadUrl,
  deleteMyNote,
  downloadNoteFile,
  getNoteStats,
  listMyNotes,
  listNotes,
} from "../controllers/notes.controller.js";
import {
  downloadS3Object,
  getDashboard,
  listS3Objects,
} from "../controllers/admin.controller.js";
import { protect } from "../middlewares/authMiddleware.js";
import { hasValidFileSignature, validateFileMetadata } from "../utils/fileValidation.js";
import {
  changePassword,
  getProfile,
  getProfilePhoto,
  loginUser,
  logoutUser,
  registerUser,
  updateProfile,
  updateProfilePhoto,
  verifyUser,
} from "../controllers/auth.controller.js";
import Note from "../models/Note.js";
import User from "../models/User.js";
import AdminAuditLog from "../models/AdminAuditLog.js";
import UserActivity from "../models/UserActivity.js";
import connectDB from "../config/db.js";
import { ensureUserId, generateUserId } from "../utils/userId.js";
import {
  hasNoteSearchCriteria,
  isDedicatedRateLimitRequest,
  isPublicNotesListRequest,
} from "../utils/rateLimitPolicy.js";
import {
  loginAccountLimiter,
  loginIpLimiter,
  notesSearchLimiter,
  notesUploadLimiter,
  passwordChangeLimiter,
  publicNotesListLimiter,
  signupLimiter,
} from "../middlewares/rateLimiters.js";
import { decryptAuthPayload, getAuthPayloadPublicKey } from "../utils/authPayloadEncryption.js";
import { s3Storage, UPLOAD_URL_TTL_SECONDS } from "../services/s3Storage.js";
import { requireHttps } from "../middlewares/requireHttps.js";

const encryptAuthPayloadForTest = (payload) => {
  const aesKey = randomBytes(32);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", aesKey, iv);
  const encryptedData = Buffer.concat([
    cipher.update(JSON.stringify(payload), "utf8"),
    cipher.final(),
    cipher.getAuthTag(),
  ]);
  const encryptedKey = publicEncrypt(
    {
      key: getAuthPayloadPublicKey(),
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    aesKey
  );

  return {
    encryptedKey: encryptedKey.toString("base64"),
    iv: iv.toString("base64"),
    encryptedData: encryptedData.toString("base64"),
  };
};

test("encrypted auth requests decrypt to the original user fields", () => {
  const payload = {
    email: "private@example.com",
    password: "safe-test-password",
    name: "Test User",
  };
  const req = { body: encryptAuthPayloadForTest(payload) };
  let continued = false;
  let responseStatus;
  let responseBody;

  decryptAuthPayload(
    req,
    {
      status(status) {
        responseStatus = status;
        return this;
      },
      json(body) {
        responseBody = body;
        return this;
      },
    },
    () => { continued = true; }
  );

  assert.equal(continued, true);
  assert.deepEqual(req.body, payload);
  assert.equal(responseStatus, undefined);
  assert.equal(responseBody, undefined);
});

test("invalid encrypted auth requests are rejected without exposing details", () => {
  let responseStatus;
  let responseBody;

  decryptAuthPayload(
    { body: { encryptedKey: "invalid", iv: "invalid", encryptedData: "invalid" } },
    {
      status(status) {
        responseStatus = status;
        return this;
      },
      json(body) {
        responseBody = body;
        return this;
      },
    },
    () => assert.fail("next should not run for invalid encrypted requests")
  );

  assert.equal(responseStatus, 400);
  assert.deepEqual(responseBody, { message: "Encrypted request payload is invalid" });
});

test("tampered encrypted authentication payloads are rejected", () => {
  const encryptedPayload = encryptAuthPayloadForTest({
    email: "private@example.test",
    password: "safe-test-password",
  });
  const encryptedData = Buffer.from(encryptedPayload.encryptedData, "base64");
  encryptedData[0] ^= 0xff;
  encryptedPayload.encryptedData = encryptedData.toString("base64");
  let responseStatus;
  let responseBody;

  decryptAuthPayload(
    { body: encryptedPayload },
    {
      status(status) { responseStatus = status; return this; },
      json(body) { responseBody = body; return this; },
    },
    () => assert.fail("tampered encrypted payload must not be accepted")
  );

  assert.equal(responseStatus, 400);
  assert.deepEqual(responseBody, { message: "Encrypted request payload is invalid" });
});

test("the auth encryption-key API exposes only the protocol-required public key", async () => {
  const app = express();
  app.use("/api/auth", authRoutes);
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  try {
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const response = await fetch(`http://127.0.0.1:${address.port}/api/auth/encryption-key`);
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.equal(body.publicKey, getAuthPayloadPublicKey());
    assert.equal(Object.keys(body).length, 1);
    assert.equal(body.publicKey.includes("PRIVATE KEY"), false);
  } finally {
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
});

test("production APIs reject insecure HTTP and accept trusted HTTPS forwarding", async () => {
  const app = express();
  app.set("trust proxy", 1);
  app.use(requireHttps);
  app.get("/health", (_req, res) => res.json({ success: true }));
  const server = app.listen(0, "127.0.0.1");
  const originalEnvironment = process.env.NODE_ENV;
  process.env.NODE_ENV = "production";

  try {
    await new Promise((resolve) => server.once("listening", resolve));
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const insecureResponse = await fetch(`http://127.0.0.1:${address.port}/health`);
    assert.equal(insecureResponse.status, 426);
    assert.deepEqual(await insecureResponse.json(), { message: "HTTPS is required" });

    const secureResponse = await fetch(`http://127.0.0.1:${address.port}/health`, {
      headers: { "x-forwarded-proto": "https" },
    });
    assert.equal(secureResponse.status, 200);
    assert.deepEqual(await secureResponse.json(), { success: true });
  } finally {
    if (originalEnvironment === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = originalEnvironment;
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
});

test("production MongoDB connections require TLS", async () => {
  const originalConnect = mongoose.connect;
  const originalEnvironment = process.env.NODE_ENV;
  const originalMongoUri = process.env.MONGO_URI;
  let connectionOptions;
  process.env.NODE_ENV = "production";
  process.env.MONGO_URI = "mongodb://database.example.test/noteshub";
  mongoose.connect = async (_uri, options) => {
    connectionOptions = options;
  };

  try {
    await connectDB();
    assert.equal(connectionOptions.tls, true);
  } finally {
    mongoose.connect = originalConnect;
    if (originalEnvironment === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = originalEnvironment;
    if (originalMongoUri === undefined) delete process.env.MONGO_URI;
    else process.env.MONGO_URI = originalMongoUri;
  }
});

test("encrypted auth requests reject additional plaintext fields", () => {
  const encryptedPayload = encryptAuthPayloadForTest({
    email: "private@example.com",
    password: "safe-test-password",
  });
  let responseStatus;

  decryptAuthPayload(
    { body: { ...encryptedPayload, password: "plaintext-password" } },
    {
      status(status) {
        responseStatus = status;
        return this;
      },
      json() { return this; },
    },
    () => assert.fail("next should not run when plaintext fields are present")
  );

  assert.equal(responseStatus, 400);
});

test("password hashes are excluded from normal user queries", () => {
  assert.equal(User.schema.path("password").options.select, false);
});

test("user IDs are unique ten-digit strings in the user and note schemas", () => {
  const userId = User.schema.path("user_id");
  assert.equal(userId.instance, "String");
  assert.equal(userId.options.match.source, "^\\d{10}$");
  assert.equal(generateUserId().length, 10);
  assert.ok(User.schema.indexes().some(([index, options]) =>
    index.user_id === 1 &&
    options.unique === true &&
    options.partialFilterExpression.user_id.$type === "string"
  ));
  assert.equal(Note.schema.path("user_id").instance, "String");
});

test("legacy users receive a unique user ID when they next upload", async () => {
  let saveAttempts = 0;
  const user = {
    async save() {
      saveAttempts += 1;
      if (saveAttempts === 1) {
        const error = new Error("Duplicate user ID");
        error.code = 11000;
        error.keyPattern = { user_id: 1 };
        throw error;
      }
    },
  };

  const userId = await ensureUserId(user);

  assert.match(userId, /^\d{10}$/);
  assert.equal(user.user_id, userId);
  assert.equal(saveAttempts, 2);
});

test("notes reference their user by the schema-generated MongoDB ID", () => {
  const uploadedBy = Note.schema.path("uploadedBy");
  assert.equal(User.schema.path("_id").instance, "ObjectId");
  assert.equal(uploadedBy.instance, "ObjectId");
  assert.equal(uploadedBy.options.ref, "User");
  assert.equal(uploadedBy.isRequired, true);
});

test("public notes listing and search have dedicated policies apart from general API traffic", () => {
  const listingRequest = { method: "GET", originalUrl: "/api/notes" };
  const statsRequest = { method: "GET", originalUrl: "/api/notes/stats" };
  assert.equal(isPublicNotesListRequest(listingRequest), true);
  assert.equal(isPublicNotesListRequest(statsRequest), false);
  assert.equal(isDedicatedRateLimitRequest(listingRequest), true);
  assert.equal(isDedicatedRateLimitRequest(statsRequest), false);
  assert.equal(hasNoteSearchCriteria({ query: { q: "linear algebra" } }), true);
  assert.equal(hasNoteSearchCriteria({ query: { q: ["linear algebra"] } }), true);
  assert.equal(hasNoteSearchCriteria({ query: { page: "2", limit: "30" } }), false);
  assert.equal(isDedicatedRateLimitRequest({ method: "GET", path: "/api/notes/123/file" }), false);
  assert.equal(isDedicatedRateLimitRequest({ method: "GET", path: "/api/auth/verify" }), false);
});

test("upload APIs require authentication while shared note reads remain public", () => {
  const routes = authRoutes.stack
    .map((layer) => layer.route)
    .filter(Boolean);
  const loginRoute = routes.find((route) => route.path === "/login");
  const signupRoute = routes.find((route) => route.path === "/register");
  const changePasswordRoute = routes.find((route) => route.path === "/change-password");

  assert.ok(loginRoute?.stack.some((layer) => layer.handle === loginIpLimiter));
  assert.ok(loginRoute?.stack.some((layer) => layer.handle === loginAccountLimiter));
  assert.ok(signupRoute?.stack.some((layer) => layer.handle === signupLimiter));
  assert.ok(changePasswordRoute);
  assert.ok(changePasswordRoute.stack.some((layer) => layer.handle === protect));
  assert.ok(changePasswordRoute.stack.some((layer) => layer.handle === passwordChangeLimiter));
  assert.equal(routes.some((route) => route.path === "/forgot-password"), false);

  for (const path of ["/verify", "/profile/photo", "/profile", "/change-password"]) {
    const route = routes.find((candidate) => candidate.path === path);
    assert.ok(route, `${path} route should exist`);
    assert.ok(route.stack.some((layer) => layer.handle === protect), `${path} should require authentication`);
  }

  const noteRoutes = notesRoutes.stack
    .map((layer) => layer.route)
    .filter(Boolean);
  const statsRoute = noteRoutes.find((route) => route.path === "/stats");
  assert.ok(statsRoute);
  assert.equal(statsRoute.stack.some((layer) => layer.handle === protect), false);
  for (const path of ["/", "/stats", "/:id/file"]) {
    const route = noteRoutes.find((candidate) => candidate.path === path);
    assert.ok(route, `${path} note route should exist`);
    assert.equal(route.stack.some((layer) => layer.handle === protect), false, `${path} should be public`);
  }
  for (const path of ["/upload/presign", "/upload/complete", "/upload", "/mine", "/:id"]) {
    const route = noteRoutes.find((candidate) => candidate.path === path);
    assert.ok(route, `${path} note route should exist`);
    assert.ok(route.stack.some((layer) => layer.handle === protect), `${path} should require authentication`);
  }
  const uploadPresignRoute = noteRoutes.find((route) => route.path === "/upload/presign");
  const publicListRoute = noteRoutes.find((route) => route.path === "/");
  assert.ok(uploadPresignRoute.stack.some((layer) => layer.handle === notesUploadLimiter));
  assert.ok(publicListRoute.stack.some((layer) => layer.handle === notesSearchLimiter));
  assert.ok(publicListRoute.stack.some((layer) => layer.handle === publicNotesListLimiter));
});

test("logout clears the authentication cookie without returning it", () => {
  const clearedCookies = [];
  let responseBody;
  const response = {
    clearCookie(name, options) {
      clearedCookies.push({ name, options });
      return this;
    },
    json(body) {
      responseBody = body;
      return this;
    },
  };

  logoutUser({}, response);

  assert.ok(clearedCookies.some(({ name }) => name === "token"));
  assert.equal("token" in responseBody, false);
  assert.equal("password" in responseBody, false);
});

test("unauthenticated protected requests are rejected", () => {
  let responseStatus;
  let responseBody;
  const response = {
    status(status) {
      responseStatus = status;
      return this;
    },
    json(body) {
      responseBody = body;
      return this;
    },
  };

  protect({ cookies: {} }, response, () => assert.fail("next should not run"));

  assert.equal(responseStatus, 401);
  assert.deepEqual(responseBody, { message: "Unauthorized: No token provided" });
});

test("protected sessions enforce current account status", async () => {
  const originalJwtSecret = process.env.JWT_SECRET;
  const originalFindById = User.findById;
  process.env.JWT_SECRET = "test-jwt-secret-that-is-long-enough-for-tests";
  const userId = new mongoose.Types.ObjectId().toString();
  const token = jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: 3600 });

  try {
    for (const [user, expectedStatus] of [
      [{ _id: userId, accountStatus: "suspended", deletedAt: null }, 403],
      [{ _id: userId, accountStatus: "active", deletedAt: new Date() }, 401],
    ]) {
      User.findById = () => ({ select: async () => user });
      let responseStatus;
      const response = {
        status(status) { responseStatus = status; return this; },
        json() { return this; },
      };
      await protect({ cookies: { token } }, response, () => assert.fail("next should not run"));
      assert.equal(responseStatus, expectedStatus);
    }

    User.findById = () => ({
      select: async () => ({ _id: userId, accountStatus: "active", deletedAt: null }),
    });
    let nextCalled = false;
    await protect({ cookies: { token } }, {}, () => { nextCalled = true; });
    assert.equal(nextCalled, true);
  } finally {
    User.findById = originalFindById;
    if (originalJwtSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = originalJwtSecret;
  }
});

test("session verification returns authentication state without profile or credential data", async () => {
  const user = { _id: "private-user-id" };
  let responseBody;
  const headers = {};
  await verifyUser(
    {
      user: { id: user._id, iat: 1, exp: Math.floor(Date.now() / 1000) + 3600 },
      authenticatedUser: user,
    },
    {
      setHeader(name, value) { headers[name] = value; },
      json(body) { responseBody = body; },
    }
  );

  assert.equal(responseBody.isAuthenticated, true);
  assert.equal(typeof responseBody.expiresAt, "number");
  assert.equal("user" in responseBody, false);
  for (const field of ["email", "password", "accessToken", "refreshToken", "sessionId"]) {
    assert.equal(field in responseBody, false);
  }
  assert.equal(headers["Cache-Control"], "no-store");
});

test("session verification does not read or migrate profile photo data", async () => {
  const userId = new mongoose.Types.ObjectId().toString();
  let userLookedUp = false;
  const originalFindById = User.findById;
  User.findById = () => {
    userLookedUp = true;
    throw new Error("session verification must not query user again");
  };
  const user = { _id: userId };
  let responseBody;

  try {
    await verifyUser(
      {
        user: { id: userId, iat: 1, exp: Math.floor(Date.now() / 1000) + 3600 },
        authenticatedUser: user,
      },
      {
        setHeader() {},
        json(body) { responseBody = body; },
      }
    );
  } finally {
    User.findById = originalFindById;
  }

  assert.deepEqual(Object.keys(responseBody).sort(), ["expiresAt", "isAuthenticated"]);
  assert.equal(userLookedUp, false);
});

test("authenticated profile response contains only the caller's profile DTO", async () => {
  const originalFindById = User.findById;
  const user = {
    user_id: "9876543210",
    name: "Jane Doe",
    email: "jane@example.test",
    university: "Example University",
    course: "Engineering",
    year: "2026",
    role: "ADMIN",
    profilePhotoS3Key: "photos/private-s3-object-key",
    password: "must-not-be-selected",
    __v: 2,
  };
  let responseBody;
  const headers = {};
  User.findById = () => ({ select: async () => user });

  try {
    await getProfile(
      { user: { id: "private-mongo-id" } },
      {
        setHeader(name, value) { headers[name] = value; },
        json(body) { responseBody = body; },
      }
    );
  } finally {
    User.findById = originalFindById;
  }

  assert.deepEqual(responseBody, {
    success: true,
    user: {
      id: "9876543210",
      name: "Jane Doe",
      email: "jane@example.test",
      university: "Example University",
      course: "Engineering",
      year: "2026",
      profilePhotoUrl: "/api/auth/profile/photo",
    },
  });
  assert.equal(JSON.stringify(responseBody).includes("private-s3-object-key"), false);
  assert.equal(JSON.stringify(responseBody).includes("must-not-be-selected"), false);
  assert.equal(headers["Cache-Control"], "no-store");
});

test("upload validation checks file contents against the declared type", () => {
  assert.equal(
    hasValidFileSignature({
      mimetype: "application/pdf",
      buffer: Buffer.from("%PDF-1.7"),
    }),
    true
  );
  assert.equal(
    hasValidFileSignature({
      mimetype: "application/pdf",
      buffer: Buffer.from("<html>not a PDF</html>"),
    }),
    false
  );
  assert.equal(
    hasValidFileSignature({
      mimetype: "image/png",
      buffer: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    }),
    true
  );
});

test("shared note responses omit storage and ownership internals", async () => {
  const originalFind = Note.find;
  const originalCountDocuments = Note.countDocuments;
  const originalListNoteRecordPage = s3Storage.listNoteRecordPage;
  let query;
  const publicNote = {
    id: "note-id",
    title: "Shared notes",
    description: "Public study notes",
    fileName: "notes.pdf",
    fileSize: 100,
    university: "Example University",
    course: "Engineering",
    studyType: "Notes",
    year: 2026,
    tags: [],
    createdAt: new Date("2026-01-01T00:00:00.000Z"),
    fileId: "private-storage-id",
    contentType: "application/pdf",
    uploadedBy: "private-user-id",
    __v: 0,
  };
  let responseBody;
  const response = {
    json(body) {
      responseBody = body;
      return this;
    },
  };

  Note.find = (filter) => {
    query = filter;
    return {
      sort() {
        return this;
      },
      skip() {
        return this;
      },
      limit() {
        return this;
      },
      select() {
        return Promise.resolve([publicNote]);
      },
    };
  };
  Note.countDocuments = async () => 1;
  s3Storage.listNoteRecordPage = async () => ({ records: [], total: 0 });

  try {
    await listNotes({}, response);
  } finally {
    Note.find = originalFind;
    Note.countDocuments = originalCountDocuments;
    s3Storage.listNoteRecordPage = originalListNoteRecordPage;
  }

  assert.equal(responseBody.success, true);
  assert.equal(responseBody.notes.length, 1);
  assert.equal(responseBody.notes[0].title, "Shared notes");
  assert.equal(responseBody.notes[0].fileUrl, "/api/notes/note-id/file");
  assert.deepEqual(query, {
    visibility: { $ne: "private" },
    uploadStatus: { $ne: "deleting" },
  });
  for (const privateField of ["fileId", "s3Key", "storageProvider", "contentType", "uploadedBy", "__v"]) {
    assert.equal(privateField in responseBody.notes[0], false);
  }
});

test("public listings include S3-only note records and exclude private notes", async () => {
  const originalFind = Note.find;
  const originalCountDocuments = Note.countDocuments;
  const originalListNoteRecordPage = s3Storage.listNoteRecordPage;
  const publicId = "imported notes 2024";
  Note.find = () => ({
    sort() {
      return this;
    },
    skip() {
      return this;
    },
    limit() {
      return this;
    },
    select: async () => [],
  });
  Note.countDocuments = async () => 0;
  s3Storage.listNoteRecordPage = async () => ({
    total: 2,
    records: [{
      _id: publicId,
      title: "S3-only note",
      fileName: "lecture.pdf",
      fileSize: 123,
      visibility: "public",
      uploadedBy: "private-owner-id",
      s3Key: "notes/private-owner-id/file",
      contentType: "application/pdf",
      createdAt: "2026-01-01T00:00:00.000Z",
    },
    {
      _id: "b9c84b91-d865-42e5-bd2f-2030d9663209",
      title: "Private note",
      fileName: "private.pdf",
      visibility: "private",
      uploadStatus: "active",
    }],
  });
  let responseBody;

  try {
    await listNotes({}, { json: (body) => { responseBody = body; } });
  } finally {
    Note.find = originalFind;
    Note.countDocuments = originalCountDocuments;
    s3Storage.listNoteRecordPage = originalListNoteRecordPage;
  }

  assert.equal(responseBody.notes.length, 1);
  assert.equal(responseBody.notes[0]._id, publicId);
  assert.equal(responseBody.notes[0].fileUrl, "/api/notes/imported%20notes%202024/file");
  assert.equal("uploadedBy" in responseBody.notes[0], false);
  assert.equal("s3Key" in responseBody.notes[0], false);
});

test("unauthenticated requests can load the public notes list", async () => {
  const originalFind = Note.find;
  const originalCountDocuments = Note.countDocuments;
  const originalListNoteRecordPage = s3Storage.listNoteRecordPage;
  const publicNote = {
    id: "public-note-id",
    title: "Public notes",
    description: "Available without logging in",
    fileName: "notes.pdf",
    fileSize: 100,
    createdAt: new Date("2026-01-01T00:00:00.000Z"),
  };
  Note.find = () => ({
    sort() {
      return this;
    },
    skip() {
      return this;
    },
    limit() {
      return this;
    },
    select: async () => [publicNote],
  });
  Note.countDocuments = async () => 1;
  s3Storage.listNoteRecordPage = async () => ({ records: [], total: 0 });

  const app = express();
  app.use("/api/notes", notesRoutes);
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));

  try {
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const response = await fetch(`http://127.0.0.1:${address.port}/api/notes`, {
      credentials: "omit",
    });
    const responseBody = await response.json();

    assert.equal(response.status, 200);
    assert.equal(responseBody.success, true);
    assert.equal(responseBody.notes[0].title, "Public notes");
  } finally {
    Note.find = originalFind;
    Note.countDocuments = originalCountDocuments;
    s3Storage.listNoteRecordPage = originalListNoteRecordPage;
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
});

test("public note statistics return counts only", async () => {
  const originalCountDocuments = Note.countDocuments;
  const originalDistinct = Note.distinct;
  const originalListNoteRecords = s3Storage.listNoteRecords;
  let responseBody;
  Note.countDocuments = async () => 3;
  Note.distinct = async (field) =>
    field === "university"
      ? ["Example University", "", null]
      : ["Notes", "Assignments"];
  s3Storage.listNoteRecords = async () => [];

  try {
    await getNoteStats({}, { json: (body) => { responseBody = body; } });
  } finally {
    Note.countDocuments = originalCountDocuments;
    Note.distinct = originalDistinct;
    s3Storage.listNoteRecords = originalListNoteRecords;
  }

  assert.deepEqual(responseBody, {
    success: true,
    stats: { total: 3, universities: 1, studyTypes: 2 },
  });
  assert.equal("notes" in responseBody, false);
});

test("public note listing reports missing S3 configuration as unavailable", async () => {
  const savedBucket = process.env.AWS_S3_BUCKET;
  delete process.env.AWS_S3_BUCKET;
  let responseStatus;
  let responseBody;
  const response = {
    status(status) {
      responseStatus = status;
      return this;
    },
    json(body) {
      responseBody = body;
      return this;
    },
  };

  try {
    await listNotes({ query: {} }, response);
  } finally {
    if (savedBucket === undefined) delete process.env.AWS_S3_BUCKET;
    else process.env.AWS_S3_BUCKET = savedBucket;
  }

  assert.equal(responseStatus, 503);
  assert.deepEqual(responseBody, { message: "Notes storage is not configured" });
});

test("public note listing requests one page from S3 and MongoDB", async () => {
  const originals = {
    find: Note.find,
    countDocuments: Note.countDocuments,
    listNoteRecordPage: s3Storage.listNoteRecordPage,
  };
  let s3PageRequest;
  let mongoSkip;
  const notes = Array.from({ length: 30 }, (_, index) => ({
    _id: `note-${index}`,
    title: `Note ${index}`,
    fileName: `note-${index}.pdf`,
    createdAt: new Date(2026, 0, 30 - index),
  }));
  Note.find = () => ({
    sort() {
      return this;
    },
    skip(value) {
      mongoSkip = value;
      return this;
    },
    limit() {
      return this;
    },
    select: async () => notes,
  });
  Note.countDocuments = async () => 90;
  s3Storage.listNoteRecordPage = async (request) => {
    s3PageRequest = request;
    return { records: [], total: 0 };
  };
  let responseBody;

  try {
    await listNotes(
      { query: { page: "2", limit: "50" } },
      { json: (body) => { responseBody = body; } }
    );
  } finally {
    Note.find = originals.find;
    Note.countDocuments = originals.countDocuments;
    s3Storage.listNoteRecordPage = originals.listNoteRecordPage;
  }

  assert.deepEqual(s3PageRequest, { offset: 30, limit: 30 });
  assert.equal(mongoSkip, 30);
  assert.equal(responseBody.notes.length, 30);
  assert.equal(responseBody.pagination.page, 2);
  assert.equal(responseBody.pagination.limit, 30);
  assert.equal(responseBody.pagination.total, 90);
});

test("note deletion is scoped to the authenticated owner", async () => {
  const originalFindOne = Note.findOne;
  const originalGetNoteRecord = s3Storage.getNoteRecord;
  const authenticatedUserId = "authenticated-user-id";
  let query;
  let responseStatus;
  const response = {
    status(status) {
      responseStatus = status;
      return this;
    },
    json() {
      return this;
    },
  };
  Note.findOne = (filter) => {
    query = filter;
    return { select: async () => null };
  };
  s3Storage.getNoteRecord = async () => null;

  try {
    await deleteMyNote(
      {
        params: { id: "6addced159123fc5d9b6b585" },
        user: { id: authenticatedUserId },
      },
      response
    );
  } finally {
    Note.findOne = originalFindOne;
    s3Storage.getNoteRecord = originalGetNoteRecord;
  }

  assert.equal(query.uploadedBy, authenticatedUserId);
  assert.equal(responseStatus, 404);
});

test("note upload URLs validate metadata and bind the upload to the authenticated user", async () => {
  const originalCreateUploadUrl = s3Storage.createUploadUrl;
  const originalFindUserById = User.findById;
  const originalJwtSecret = process.env.JWT_SECRET;
  const ownerId = "65aabbccddeeff0011223344";
  const userId = "1234567890";
  const createdKeys = [];
  let responseBody;
  let responseStatus;
  process.env.JWT_SECRET = "test-jwt-secret-that-is-long-enough-for-tests";
  User.findById = () => ({ select: async () => ({ name: "Example User" }) });
  s3Storage.createUploadUrl = async ({ key }) => {
    createdKeys.push(key);
    return "https://signed-upload.example.test";
  };

  try {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      await createNoteUploadUrl(
        {
          user: { id: ownerId, user_id: userId },
          body: {
            fileName: "../../course-notes.pdf",
            contentType: "application/pdf",
            fileSize: 100,
            visibility: "private",
            title: "Course notes",
          },
        },
        {
          setHeader() {},
          status(status) {
            responseStatus = status;
            return this;
          },
          json(body) {
            responseBody = body;
            return this;
          },
        },
      );
    }
  } finally {
    s3Storage.createUploadUrl = originalCreateUploadUrl;
    User.findById = originalFindUserById;
    if (originalJwtSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = originalJwtSecret;
  }

  assert.equal(responseStatus, 201);
  assert.equal(createdKeys.length, 2);
  assert.notEqual(createdKeys[0], createdKeys[1]);
  assert.ok(
    createdKeys.every((key) =>
      new RegExp(`^notes/example-user-${userId}/course-notes-${userId}-[0-9a-f-]{36}$`).test(key)
    )
  );
  assert.equal(responseBody.uploadUrl, "https://signed-upload.example.test");
  assert.deepEqual(responseBody.headers, {
    "Content-Type": "application/pdf",
    "x-amz-server-side-encryption": "AES256",
  });
  const claims = jwt.verify(responseBody.uploadToken, "test-jwt-secret-that-is-long-enough-for-tests", {
    algorithms: ["HS256"],
  });
  assert.equal(claims.visibility, "private");
  assert.ok(claims.noteId.startsWith(`course-notes-${userId}-`));
  assert.equal(claims.key, createdKeys.at(-1));
  assert.equal("AWS_ACCESS_KEY_ID" in responseBody, false);
  assert.equal("AWS_SECRET_ACCESS_KEY" in responseBody, false);
});

test("presign rejects unsupported and oversized files before contacting S3", async () => {
  const originalCreateUploadUrl = s3Storage.createUploadUrl;
  const originalMaxSize = process.env.MAX_NOTE_FILE_SIZE_BYTES;
  let storageCalled = false;
  let responseStatus;
  s3Storage.createUploadUrl = async () => {
    storageCalled = true;
    return "https://signed-upload.example.test";
  };
  process.env.MAX_NOTE_FILE_SIZE_BYTES = "10";

  const invokePresign = async (body) => {
    responseStatus = undefined;
    await createNoteUploadUrl(
      { user: { id: "65aabbccddeeff0011223344" }, body },
      {
        status(status) {
          responseStatus = status;
          return this;
        },
        json() {
          return this;
        },
      }
    );
    return responseStatus;
  };

  try {
    assert.equal(
      await invokePresign({
        fileName: "payload.exe",
        contentType: "application/pdf",
        fileSize: 5,
      }),
      400
    );
    assert.equal(
      await invokePresign({
        fileName: "notes.pdf",
        contentType: "application/pdf",
        fileSize: 11,
      }),
      413
    );
  } finally {
    s3Storage.createUploadUrl = originalCreateUploadUrl;
    if (originalMaxSize === undefined) delete process.env.MAX_NOTE_FILE_SIZE_BYTES;
    else process.env.MAX_NOTE_FILE_SIZE_BYTES = originalMaxSize;
  }

  assert.equal(storageCalled, false);
});

test("S3 PUT signatures bind the exact file size and expire quickly", async () => {
  const savedEnvironment = {
    AWS_REGION: process.env.AWS_REGION,
    AWS_S3_BUCKET: process.env.AWS_S3_BUCKET,
    AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
  };
  process.env.AWS_REGION = "ap-south-1";
  process.env.AWS_S3_BUCKET = "notes-test-bucket";
  process.env.AWS_ACCESS_KEY_ID = "test-access-key";
  process.env.AWS_SECRET_ACCESS_KEY = "test-secret-key";

  try {
    const url = new URL(
      await s3Storage.createUploadUrl({
        key: "notes/test-user/unique-object",
        contentType: "application/pdf",
        fileSize: 123,
      })
    );
    const signedHeaders = url.searchParams.get("X-Amz-SignedHeaders")?.split(";") || [];
    assert.ok(signedHeaders.includes("content-length"));
    assert.ok(signedHeaders.includes("x-amz-server-side-encryption"));
    assert.equal(url.searchParams.get("X-Amz-Expires"), String(UPLOAD_URL_TTL_SECONDS));
  } finally {
    for (const [name, value] of Object.entries(savedEnvironment)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});

test("profile photos are stored in the photos S3 prefix with encryption", async () => {
  const savedEnvironment = {
    AWS_REGION: process.env.AWS_REGION,
    AWS_S3_BUCKET: process.env.AWS_S3_BUCKET,
    AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
  };
  const originalSend = S3Client.prototype.send;
  const image = Buffer.from([0x89, 0x50, 0x4e, 0x47]);
  let uploadedCommand;
  const commands = [];
  process.env.AWS_REGION = "ap-south-1";
  process.env.AWS_S3_BUCKET = "notes-test-bucket";
  process.env.AWS_ACCESS_KEY_ID = "test-access-key";
  process.env.AWS_SECRET_ACCESS_KEY = "test-secret-key";
  S3Client.prototype.send = async (command) => {
    commands.push(command);
    if (command instanceof PutObjectCommand) uploadedCommand = command;
    if (command instanceof HeadObjectCommand) {
      return {
        ETag: '"profile-etag"',
        LastModified: new Date("2026-01-02T03:04:05.000Z"),
        StorageClass: "STANDARD",
        ContentLength: image.length,
        Metadata: { source: "profile" },
      };
    }
  };

  try {
    const metadata = await s3Storage.putProfilePhoto({
      key: "photos/jane-doe-1234567890",
      body: image,
      contentType: "image/png",
    });
    assert.deepEqual(metadata, {
      bucket: "notes-test-bucket",
      etag: '"profile-etag"',
      lastModified: new Date("2026-01-02T03:04:05.000Z"),
      storageClass: "STANDARD",
      fileSize: image.length,
      customMetadata: { source: "profile" },
    });
  } finally {
    S3Client.prototype.send = originalSend;
    for (const [name, value] of Object.entries(savedEnvironment)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }

  assert.ok(uploadedCommand instanceof PutObjectCommand);
  assert.equal(uploadedCommand.input.Bucket, "notes-test-bucket");
  assert.equal(uploadedCommand.input.Key, "photos/jane-doe-1234567890");
  assert.equal(uploadedCommand.input.Body, image);
  assert.equal(uploadedCommand.input.ContentType, "image/png");
  assert.equal(uploadedCommand.input.ServerSideEncryption, "AES256");
  assert.equal(uploadedCommand.input.CacheControl, "private, no-store");
  assert.ok(commands[1] instanceof HeadObjectCommand);
});

test("notes without a matching Mongo user do not write metadata to S3", async () => {
  const savedEnvironment = {
    AWS_REGION: process.env.AWS_REGION,
    AWS_S3_BUCKET: process.env.AWS_S3_BUCKET,
    AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
  };
  const originalSend = S3Client.prototype.send;
  const originalUserExists = User.exists;
  const uploadedCommands = [];
  const ownerId = new mongoose.Types.ObjectId().toString();
  const noteId = "7c78e950-3026-4fef-8290-0e4508aa2718";
  process.env.AWS_REGION = "ap-south-1";
  process.env.AWS_S3_BUCKET = "notes-test-bucket";
  process.env.AWS_ACCESS_KEY_ID = "test-access-key";
  process.env.AWS_SECRET_ACCESS_KEY = "test-secret-key";
  S3Client.prototype.send = async (command) => { uploadedCommands.push(command); };
  User.exists = async () => null;

  try {
    const saved = await s3Storage.putNoteRecord({
      _id: noteId,
      uploadedBy: ownerId,
      s3Key: "notes/test.pdf",
      title: "Test",
      fileName: "test.pdf",
      contentType: "application/pdf",
      fileSize: 1,
    });
    assert.equal(saved, null);
  } finally {
    S3Client.prototype.send = originalSend;
    User.exists = originalUserExists;
    for (const [name, value] of Object.entries(savedEnvironment)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }

  assert.equal(uploadedCommands.length, 0);
});

test("note records use MongoDB when their owner can be resolved", async () => {
  const savedEnvironment = {
    AWS_REGION: process.env.AWS_REGION,
    AWS_S3_BUCKET: process.env.AWS_S3_BUCKET,
    AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
  };
  const originals = {
    send: S3Client.prototype.send,
    userExists: User.exists,
    findOne: Note.findOne,
    findOneAndUpdate: Note.findOneAndUpdate,
  };
  const ownerId = new mongoose.Types.ObjectId();
  const noteId = "7c78e950-3026-4fef-8290-0e4508aa2718";
  const note = {
    _id: noteId,
    uploadedBy: ownerId.toString(),
    s3Key: `notes/${ownerId}/upload.pdf`,
    title: "Mongo note",
    fileName: "upload.pdf",
    contentType: "application/pdf",
    fileSize: 9,
    visibility: "private",
    uploadStatus: "active",
  };
  let update;
  process.env.AWS_REGION = "ap-south-1";
  process.env.AWS_S3_BUCKET = "notes-test-bucket";
  process.env.AWS_ACCESS_KEY_ID = "test-access-key";
  process.env.AWS_SECRET_ACCESS_KEY = "test-secret-key";
  User.exists = async () => true;
  Note.findOne = () => ({ lean: async () => null });
  Note.findOneAndUpdate = (_query, updateDocument) => {
    update = updateDocument;
    return { lean: async () => ({ ...note, s3MetadataId: noteId }) };
  };
  S3Client.prototype.send = async () => assert.fail("Mapped note metadata must not be written to S3");

  try {
    const saved = await s3Storage.putNoteRecord(note);
    assert.equal(saved._id, noteId);
    assert.equal(update.$set.s3MetadataId, noteId);
    assert.equal(update.$set.uploadedBy.toString(), ownerId.toString());
    assert.equal(update.$set.s3ObjectMetadata.bucket, "notes-test-bucket");
  } finally {
    S3Client.prototype.send = originals.send;
    User.exists = originals.userExists;
    Note.findOne = originals.findOne;
    Note.findOneAndUpdate = originals.findOneAndUpdate;
    for (const [name, value] of Object.entries(savedEnvironment)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});

test("user note index reads only that account's indexed note records from MongoDB", async () => {
  const ownerId = new mongoose.Types.ObjectId().toString();
  const noteId = "7c78e950-3026-4fef-8290-0e4508aa2718";
  const originalFind = Note.find;
  Note.find = () => ({
    lean: async () => [{
      _id: noteId,
      s3MetadataId: noteId,
      uploadedBy: ownerId,
      title: "My upload",
      visibility: "private",
      uploadStatus: "active",
    }],
  });

  try {
    const records = await s3Storage.listNoteRecordsForUser({ uploadedBy: ownerId });
    assert.equal(records.length, 1);
    assert.equal(records[0].uploadedBy, ownerId);
    assert.equal(records[0].title, "My upload");
  } finally {
    Note.find = originalFind;
  }
});

test("dashboard note listing reads from MongoDB", async () => {
  const originalFindById = User.findById;
  const originalFind = Note.find;
  const originalCountDocuments = Note.countDocuments;
  const ownerId = new mongoose.Types.ObjectId().toString();
  const records = [
    { _id: "note-one", uploadedBy: ownerId, title: "First", createdAt: "2026-01-02" },
    { _id: "note-two", uploadedBy: ownerId, title: "Second", createdAt: "2026-01-01" },
  ];
  let responseBody;
  User.findById = () => ({});
  Note.find = () => ({
    sort() { return this; },
    skip() { return this; },
    limit() { return this; },
    select: async () => records,
    lean: async () => records,
  });
  Note.countDocuments = async () => 2;

  try {
    await listMyNotes(
      { user: { id: ownerId } },
      {
        setHeader() {},
        json(body) { responseBody = body; return this; },
      }
    );
  } finally {
    User.findById = originalFindById;
    Note.find = originalFind;
    Note.countDocuments = originalCountDocuments;
  }

  assert.deepEqual(responseBody.notes.map(({ title }) => title), ["First", "Second"]);
  assert.deepEqual(responseBody.pagination, { page: 1, limit: 30, total: 2, totalPages: 1 });
});

test("dashboard note listing reads only the current user's notes from MongoDB", async () => {
  const originalFindById = User.findById;
  const originalFind = Note.find;
  const originalCountDocuments = Note.countDocuments;
  const ownerId = new mongoose.Types.ObjectId().toString();
  const userNote = { _id: "legacy-note", uploadedBy: ownerId, title: "Legacy upload" };
  const foreignNote = { _id: "other-note", uploadedBy: new mongoose.Types.ObjectId().toString(), title: "Foreign" };
  let responseBody;
  User.findById = () => ({});
  Note.find = () => ({
    sort() { return this; },
    skip() { return this; },
    limit() { return this; },
    select: async () => [userNote],
    lean: async () => [userNote],
  });
  Note.countDocuments = async () => 1;

  try {
    await listMyNotes(
      { user: { id: ownerId } },
      {
        setHeader() {},
        json(body) { responseBody = body; return this; },
      }
    );
  } finally {
    User.findById = originalFindById;
    Note.find = originalFind;
    Note.countDocuments = originalCountDocuments;
  }

  assert.deepEqual(responseBody.notes.map(({ title }) => title), ["Legacy upload"]);
  assert.equal(responseBody.pagination.total, 1);
});

test("note records list from MongoDB only", async () => {
  const originalFind = Note.find;
  const currentId = "imported notes 2024";
  const legacyId = "4f4152a7-45bc-4c73-b2d0-468c8bc3c5a1";
  Note.find = () => ({
    lean: async () => [
      { _id: currentId, s3MetadataId: currentId, title: "Current", uploadStatus: "active" },
      { _id: legacyId, s3MetadataId: legacyId, title: "Legacy", uploadStatus: "active" },
    ],
  });

  try {
    const records = await s3Storage.listNoteRecords();
    assert.deepEqual(records.map(({ title }) => title).sort(), ["Current", "Legacy"]);
  } finally {
    Note.find = originalFind;
  }
});

test("note page reads only the requested MongoDB records", async () => {
  const originalFind = Note.find;
  const originalCountDocuments = Note.countDocuments;
  const ids = Array.from({ length: 75 }, (_, index) => `paged-note-${index}`);
  Note.find = () => ({
    sort() { return this; },
    skip() { return this; },
    limit() { return this; },
    select: async () => ids.slice(30, 60).map((id) => ({ _id: id, s3MetadataId: id, title: id, uploadStatus: "active" })),
    lean: async () => ids.slice(30, 60).map((id) => ({ _id: id, s3MetadataId: id, title: id, uploadStatus: "active" })),
  });
  Note.countDocuments = async () => 75;

  try {
    const result = await s3Storage.listNoteRecordPage({ offset: 30, limit: 30 });
    assert.equal(result.total, 75);
    assert.equal(result.records.length, 30);
    assert.equal(result.records[0]._id, "paged-note-30");
    assert.equal(result.records[29]._id, "paged-note-59");
  } finally {
    Note.find = originalFind;
    Note.countDocuments = originalCountDocuments;
  }
});

test("note records are fetched from MongoDB without S3 requests", async () => {
  const originalFind = Note.find;
  const ids = Array.from({ length: 30 }, (_, index) => `note-${index}`);
  Note.find = () => ({
    lean: async () => ids.map((id) => ({ _id: id, s3MetadataId: id, title: id, uploadStatus: "active" })),
  });

  try {
    const records = await s3Storage.listNoteRecords();
    assert.equal(records.length, ids.length);
  } finally {
    Note.find = originalFind;
  }
});

test("admin dashboard deduplicates valid recent-note uploader IDs", async () => {
  const originals = {
    userAggregate: User.aggregate,
    userFind: User.find,
    userCountDocuments: User.countDocuments,
    noteAggregate: Note.aggregate,
    noteFind: Note.find,
    auditFind: AdminAuditLog.find,
    activityCountDocuments: UserActivity.countDocuments,
  };
  const userId = new mongoose.Types.ObjectId();
  const uploaderId = new mongoose.Types.ObjectId();
  const invalidUploaderId = "not-an-object-id";
  const recentUser = {
    _id: userId,
    user_id: "1234567890",
    name: "Recent User",
    email: "recent@example.test",
    createdAt: new Date("2026-01-03T00:00:00Z"),
  };
  const recentNotes = [
    {
      _id: new mongoose.Types.ObjectId(),
      title: "Uploaded note",
      fileName: "note.pdf",
      uploadedBy: uploaderId,
      createdAt: new Date("2026-01-02T00:00:00Z"),
    },
    {
      _id: new mongoose.Types.ObjectId(),
      title: "Legacy note",
      fileName: "legacy.pdf",
      uploadedBy: invalidUploaderId,
      createdAt: new Date("2026-01-01T00:00:00Z"),
    },
  ];
  const uploader = { _id: uploaderId, name: "Uploader", email: "uploader@example.test" };
  const thenableQuery = (result) => ({
    select() { return this; },
    sort() { return this; },
    limit() { return this; },
    populate() { return this; },
    then(resolve, reject) { return Promise.resolve(result).then(resolve, reject); },
  });
  let uploaderLookupIds;
  let responseStatus = 200;
  let responseBody;

  User.aggregate = async () => [{ _id: "active", count: 1 }];
  User.find = (filter) => {
    if (filter._id?.$in) {
      uploaderLookupIds = filter._id.$in;
      return thenableQuery([uploader]);
    }
    return thenableQuery([recentUser]);
  };
  User.countDocuments = async () => 0;
  Note.aggregate = async () => [{ _id: "public", count: 2, storageBytes: 120 }];
  Note.find = () => thenableQuery(recentNotes);
  AdminAuditLog.find = () => thenableQuery([]);
  UserActivity.countDocuments = async () => 0;

  try {
    await getDashboard({}, {
      setHeader() {},
      status(status) { responseStatus = status; return this; },
      json(body) { responseBody = body; return this; },
    });
  } finally {
    User.aggregate = originals.userAggregate;
    User.find = originals.userFind;
    User.countDocuments = originals.userCountDocuments;
    Note.aggregate = originals.noteAggregate;
    Note.find = originals.noteFind;
    AdminAuditLog.find = originals.auditFind;
    UserActivity.countDocuments = originals.activityCountDocuments;
  }

  assert.equal(responseStatus, 200);
  assert.deepEqual(uploaderLookupIds, [uploaderId.toString()]);
  assert.equal(responseBody.recentNotes[0].uploader.name, "Uploader");
  assert.equal(responseBody.recentNotes[1].uploader, null);
});

test("raw S3 inventory returns bucket objects without owner matching", async () => {
  const originalListBucketObjectPage = s3Storage.listBucketObjectPage;
  const bucketPage = {
    bucketName: "test-bucket",
    objects: [
      {
        s3Key: "notes/unmapped-owner/file.pdf",
        sizeBytes: 123,
        lastModified: "2026-01-01T00:00:00.000Z",
        eTag: "\"test-etag\"",
        storageClass: "STANDARD",
      },
    ],
    nextToken: "next-page",
  };
  let pageRequest;
  let responseStatus = 200;
  let responseBody;
  s3Storage.listBucketObjectPage = async (request) => {
    pageRequest = request;
    return bucketPage;
  };

  try {
    await listS3Objects(
      { query: { limit: "25", continuationToken: "opaque-cursor" } },
      {
        setHeader() {},
        status(status) { responseStatus = status; return this; },
        json(body) { responseBody = body; return this; },
      }
    );
  } finally {
    s3Storage.listBucketObjectPage = originalListBucketObjectPage;
  }

  assert.equal(responseStatus, 200);
  assert.deepEqual(pageRequest, { continuationToken: "opaque-cursor", limit: 25 });
  assert.deepEqual(responseBody, bucketPage);
});

test("raw S3 inventory reports missing bucket-list permission", async () => {
  const originalListBucketObjectPage = s3Storage.listBucketObjectPage;
  let responseStatus;
  let responseBody;
  s3Storage.listBucketObjectPage = async () => {
    const error = new Error("Access denied");
    error.name = "AccessDenied";
    error.$metadata = { httpStatusCode: 403 };
    throw error;
  };

  try {
    await listS3Objects(
      { query: {} },
      {
        status(status) { responseStatus = status; return this; },
        json(body) { responseBody = body; return this; },
      }
    );
  } finally {
    s3Storage.listBucketObjectPage = originalListBucketObjectPage;
  }

  assert.equal(responseStatus, 503);
  assert.match(responseBody.message, /cannot list objects/i);
});

test("raw S3 inventory endpoints require an administrator session", async () => {
  const originalListBucketObjectPage = s3Storage.listBucketObjectPage;
  const originalCreateBucketObjectDownloadUrl = s3Storage.createBucketObjectDownloadUrl;
  let s3Accessed = false;
  s3Storage.listBucketObjectPage = async () => {
    s3Accessed = true;
    return { bucketName: "test-bucket", objects: [], nextToken: null };
  };
  s3Storage.createBucketObjectDownloadUrl = async () => {
    s3Accessed = true;
    return "https://signed-download.example.test";
  };

  const app = express();
  app.use(cookieParser());
  app.use("/api/admin", adminRoutes);
  const server = app.listen(0, "127.0.0.1");

  try {
    await new Promise((resolve) => server.once("listening", resolve));
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const inventoryResponse = await fetch(
      `http://127.0.0.1:${address.port}/api/admin/media/s3-objects`
    );
    const downloadResponse = await fetch(
      `http://127.0.0.1:${address.port}/api/admin/media/s3-object/download?s3Key=notes%2Ffile.pdf`
    );
    assert.equal(inventoryResponse.status, 401);
    assert.equal(downloadResponse.status, 401);
    assert.equal(s3Accessed, false);
  } finally {
    s3Storage.listBucketObjectPage = originalListBucketObjectPage;
    s3Storage.createBucketObjectDownloadUrl = originalCreateBucketObjectDownloadUrl;
    await new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
  }
});

test("raw S3 object downloads do not require a MongoDB owner record", async () => {
  const originalCreateBucketObjectDownloadUrl = s3Storage.createBucketObjectDownloadUrl;
  const objectKey = "notes/unmapped-owner/file.pdf";
  let requestedKey;
  let redirectStatus;
  let redirectUrl;
  s3Storage.createBucketObjectDownloadUrl = async (key) => {
    requestedKey = key;
    return "https://signed-download.example.test";
  };

  try {
    await downloadS3Object(
      { query: { s3Key: objectKey } },
      {
        setHeader() { return this; },
        redirect(status, url) {
          redirectStatus = status;
          redirectUrl = url;
          return this;
        },
      }
    );
  } finally {
    s3Storage.createBucketObjectDownloadUrl = originalCreateBucketObjectDownloadUrl;
  }

  assert.equal(requestedKey, objectKey);
  assert.equal(redirectStatus, 302);
  assert.equal(redirectUrl, "https://signed-download.example.test");
});

test("S3 note lookups avoid casting UUID metadata IDs as MongoDB ObjectIds", async () => {
  const originals = {
    findOne: Note.findOne,
    deleteOne: Note.deleteOne,
  };
  const uuid = "7c78e950-3026-4fef-8290-0e4508aa2718";
  const objectId = new mongoose.Types.ObjectId().toString();
  const lookups = [];
  const deletions = [];
  Note.findOne = (filter) => {
    lookups.push(filter);
    return { lean: async () => null };
  };
  Note.deleteOne = async (filter) => {
    deletions.push(filter);
  };

  try {
    await s3Storage.getNoteRecord(uuid);
    await s3Storage.deleteNoteRecord(uuid);
    await s3Storage.getNoteRecord(objectId);
  } finally {
    Note.findOne = originals.findOne;
    Note.deleteOne = originals.deleteOne;
  }

  assert.deepEqual(lookups[0], { $or: [{ s3MetadataId: uuid }] });
  assert.deepEqual(deletions[0], { $or: [{ s3MetadataId: uuid }] });
  assert.deepEqual(lookups[1], {
    $or: [{ s3MetadataId: objectId }, { _id: objectId }],
  });
});

test("S3 upload verification checks size, MIME, encryption, and file signature", async () => {
  const savedEnvironment = {
    AWS_REGION: process.env.AWS_REGION,
    AWS_S3_BUCKET: process.env.AWS_S3_BUCKET,
    AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
  };
  const originalSend = S3Client.prototype.send;
  const commands = [];
  let bytes = Buffer.from("%PDF-test");
  let head = {
    ContentLength: 9,
    ContentType: "application/pdf",
    ServerSideEncryption: "AES256",
  };
  process.env.AWS_REGION = "ap-south-1";
  process.env.AWS_S3_BUCKET = "notes-test-bucket";
  process.env.AWS_ACCESS_KEY_ID = "test-access-key";
  process.env.AWS_SECRET_ACCESS_KEY = "test-secret-key";
  S3Client.prototype.send = async (command) => {
    commands.push(command);
    if (command instanceof HeadObjectCommand) {
      return head;
    }
    if (command instanceof GetObjectCommand) {
      return { Body: { transformToByteArray: async () => bytes } };
    }
    throw new Error("Unexpected S3 command");
  };

  try {
    assert.deepEqual(
      await s3Storage.verifyUploadedObject({
        key: "notes/test-user/document",
        contentType: "application/pdf",
        fileSize: 9,
      }),
      {
        bucket: "notes-test-bucket",
        etag: undefined,
        lastModified: undefined,
        storageClass: "STANDARD",
        customMetadata: {},
      }
    );
    assert.equal(commands[1].input.Range, "bytes=0-8");

    bytes = Buffer.from("<html>bad</html>");
    await assert.rejects(
      s3Storage.verifyUploadedObject({
        key: "notes/test-user/document",
        contentType: "application/pdf",
        fileSize: 9,
      }),
      { code: "INVALID_S3_UPLOAD" }
    );

    bytes = Buffer.from("%PDF-test");
    head = { ...head, ContentLength: 10 };
    const commandCount = commands.length;
    await assert.rejects(
      s3Storage.verifyUploadedObject({
        key: "notes/test-user/document",
        contentType: "application/pdf",
        fileSize: 9,
      }),
      { code: "INVALID_S3_UPLOAD" }
    );
    assert.equal(commands.length, commandCount + 1);
    assert.ok(commands.at(-1) instanceof HeadObjectCommand);
  } finally {
    S3Client.prototype.send = originalSend;
    for (const [name, value] of Object.entries(savedEnvironment)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});

test("S3 bucket inventory maps raw object pages and requires a next token when truncated", async () => {
  const savedEnvironment = {
    AWS_REGION: process.env.AWS_REGION,
    AWS_S3_BUCKET: process.env.AWS_S3_BUCKET,
    AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
  };
  const originalSend = S3Client.prototype.send;
  const pageResponse = {
    IsTruncated: true,
    NextContinuationToken: "next-page",
    Contents: [
      {
        Key: "notes/unmapped-owner/file.pdf",
        Size: 123,
        LastModified: new Date("2026-01-01T00:00:00.000Z"),
        ETag: "\"test-etag\"",
        StorageClass: "STANDARD_IA",
      },
      { Size: 99 },
    ],
  };
  let command;
  process.env.AWS_REGION = "ap-south-1";
  process.env.AWS_S3_BUCKET = "notes-test-bucket";
  process.env.AWS_ACCESS_KEY_ID = "test-access-key";
  process.env.AWS_SECRET_ACCESS_KEY = "test-secret-key";
  S3Client.prototype.send = async (request) => {
    command = request;
    return pageResponse;
  };

  try {
    const result = await s3Storage.listBucketObjectPage({
      continuationToken: "previous-page",
      limit: 25,
    });
    assert.ok(command instanceof ListObjectsV2Command);
    assert.deepEqual(command.input, {
      Bucket: "notes-test-bucket",
      MaxKeys: 25,
      ContinuationToken: "previous-page",
    });
    assert.deepEqual(result, {
      bucketName: "notes-test-bucket",
      objects: [
        {
          s3Key: "notes/unmapped-owner/file.pdf",
          sizeBytes: 123,
          lastModified: "2026-01-01T00:00:00.000Z",
          eTag: "\"test-etag\"",
          storageClass: "STANDARD_IA",
        },
      ],
      nextToken: "next-page",
    });

    pageResponse.NextContinuationToken = undefined;
    await assert.rejects(
      s3Storage.listBucketObjectPage({ limit: 25 }),
      /truncated object page without a continuation token/
    );
  } finally {
    S3Client.prototype.send = originalSend;
    for (const [name, value] of Object.entries(savedEnvironment)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});

test("S3 download URLs expire quickly and preserve a safe original filename", async () => {
  const savedEnvironment = {
    AWS_REGION: process.env.AWS_REGION,
    AWS_S3_BUCKET: process.env.AWS_S3_BUCKET,
    AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
  };
  process.env.AWS_REGION = "ap-south-1";
  process.env.AWS_S3_BUCKET = "notes-test-bucket";
  process.env.AWS_ACCESS_KEY_ID = "test-access-key";
  process.env.AWS_SECRET_ACCESS_KEY = "test-secret-key";

  try {
    const url = new URL(
      await s3Storage.createDownloadUrl({
        key: "notes/test-user/document",
        fileName: "résumé notes.pdf",
        contentType: "application/pdf",
      })
    );
    assert.equal(url.searchParams.get("X-Amz-Expires"), "120");
    const disposition = url.searchParams.get("response-content-disposition");
    assert.match(disposition, /attachment/);
    assert.match(disposition, /filename\*=UTF-8''r%C3%A9sum%C3%A9%20notes\.pdf/);
    assert.equal(disposition.includes("\r"), false);
    assert.equal(url.searchParams.get("response-cache-control"), "private, no-store");

    const profilePhotoUrl = new URL(
      await s3Storage.createProfilePhotoUrl({
        key: "profile-photo/jane-doe-1234567890",
        contentType: "image/png",
      })
    );
    assert.equal(profilePhotoUrl.searchParams.get("X-Amz-Expires"), "120");
    assert.equal(profilePhotoUrl.searchParams.get("response-content-disposition"), "inline");
    assert.equal(profilePhotoUrl.searchParams.get("response-content-type"), "image/png");
    assert.equal(profilePhotoUrl.searchParams.get("response-cache-control"), "private, no-store");
  } finally {
    for (const [name, value] of Object.entries(savedEnvironment)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});

test("upload validation supports every file type when mobile MIME metadata is unavailable", () => {
  const supportedFiles = [
    ["notes.pdf", "application/pdf", Buffer.from("%PDF-test")],
    ["notes.doc", "application/msword", Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])],
    ["notes.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", Buffer.from([0x50, 0x4b, 0x03, 0x04])],
    ["notes.ppt", "application/vnd.ms-powerpoint", Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])],
    ["notes.pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation", Buffer.from([0x50, 0x4b, 0x03, 0x04])],
    ["notes.xls", "application/vnd.ms-excel", Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])],
    ["notes.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", Buffer.from([0x50, 0x4b, 0x03, 0x04])],
    ["notes.txt", "text/plain", Buffer.from("notes")],
    ["notes.csv", "text/csv", Buffer.from("a,b")],
    ["notes.md", "text/markdown", Buffer.from("# notes")],
    ["notes.json", "application/json", Buffer.from("{}")],
    ["notes.xml", "application/xml", Buffer.from("<a/>")],
    ["notes.jpg", "image/jpeg", Buffer.from([0xff, 0xd8, 0xff])],
    ["notes.png", "image/png", Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])],
    ["notes.gif", "image/gif", Buffer.from("GIF89a")],
    ["notes.webp", "image/webp", Buffer.from("RIFF1234WEBP")],
  ];

  for (const [fileName, expectedContentType, buffer] of supportedFiles) {
    const result = validateFileMetadata({
      fileName,
      contentType: "application/octet-stream",
      fileSize: buffer.length,
    });
    assert.equal(result.valid, true, fileName);
    assert.equal(result.contentType, expectedContentType, fileName);
    assert.equal(
      hasValidFileSignature({ buffer, contentType: result.contentType }),
      true,
      fileName
    );
  }

  const sanitizedFile = validateFileMetadata({
    fileName: "../../notes.pdf",
    contentType: "",
    fileSize: 10,
  });
  assert.equal(sanitizedFile.safeName, "notes.pdf");
  assert.equal(sanitizedFile.contentType, "application/pdf");
  assert.equal(validateFileMetadata({
    fileName: "notes.unsupported",
    contentType: "application/pdf",
    fileSize: 10,
  }).valid, false);
  assert.equal(validateFileMetadata({
    fileName: "notes.pdf",
    contentType: "application/pdf",
    fileSize: 0,
  }).valid, false);
  const invalidPdf = validateFileMetadata({
    fileName: "notes.pdf",
    contentType: "image/png",
    fileSize: 22,
  });
  assert.equal(
    hasValidFileSignature({
      buffer: Buffer.from("<html>not a PDF</html>"),
      contentType: invalidPdf.contentType,
    }),
    false
  );
});

test("upload completion stores private note metadata without using the legacy S3 index", async () => {
  const originalFindOne = Note.findOne;
  const originalCreate = Note.create;
  const originalVerify = s3Storage.verifyUploadedObject;
  const originalGetNoteRecord = s3Storage.getNoteRecord;
  const originalPutNoteRecord = s3Storage.putNoteRecord;
  const originalJwtSecret = process.env.JWT_SECRET;
  const ownerId = "65aabbccddeeff0011223344";
  const key = `notes/${ownerId}/unique-upload-key`;
  const noteId = "7c78e950-3026-4fef-8290-0e4508aa2718";
  const verified = [];
  let storedNote;
  let responseBody;
  let responseStatus;
  process.env.JWT_SECRET = "test-jwt-secret-that-is-long-enough-for-tests";
  Note.findOne = async () => null;
  s3Storage.getNoteRecord = async () => null;
  s3Storage.verifyUploadedObject = async (object) => {
    verified.push(object);
    return { bucket: "notes-test-bucket", etag: '"upload-etag"' };
  };
  s3Storage.putNoteRecord = async (note) => {
    storedNote = note;
  };
  Note.create = async () => assert.fail("New note metadata must not be written to MongoDB");
  const uploadToken = jwt.sign(
    {
      sub: ownerId,
      key,
      noteId,
      fileName: "notes.pdf",
      contentType: "application/pdf",
      fileSize: 9,
      title: "My notes",
      description: "",
      visibility: "private",
      tags: [],
    },
    process.env.JWT_SECRET,
    { expiresIn: 60, issuer: "noteshub-s3-upload", audience: "noteshub-s3-upload" }
  );

  try {
    await completeNoteUpload(
      { user: { id: ownerId }, body: { uploadToken } },
      {
        status(status) {
          responseStatus = status;
          return this;
        },
        json(body) {
          responseBody = body;
          return this;
        },
      }
    );
  } finally {
    Note.findOne = originalFindOne;
    Note.create = originalCreate;
    s3Storage.getNoteRecord = originalGetNoteRecord;
    s3Storage.putNoteRecord = originalPutNoteRecord;
    s3Storage.verifyUploadedObject = originalVerify;
    if (originalJwtSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = originalJwtSecret;
  }

  assert.equal(responseStatus, 201);
  assert.deepEqual(verified, [{ key, contentType: "application/pdf", fileSize: 9 }]);
  assert.equal(storedNote._id, noteId);
  assert.equal(storedNote.s3Key, key);
  assert.equal(storedNote.uploadedBy, ownerId);
  assert.equal(storedNote.visibility, "private");
  assert.deepEqual(storedNote.s3ObjectMetadata, {
    bucket: "notes-test-bucket",
    etag: '"upload-etag"',
  });
  assert.equal("s3Key" in responseBody.note, false);
});

test("S3 metadata write failure after file verification cleans up the unreferenced file", async () => {
  const originals = {
    findOne: Note.findOne,
    getNoteRecord: s3Storage.getNoteRecord,
    putNoteRecord: s3Storage.putNoteRecord,
    verify: s3Storage.verifyUploadedObject,
    delete: s3Storage.deleteObject,
    jwtSecret: process.env.JWT_SECRET,
  };
  const ownerId = "65aabbccddeeff0011223344";
  const key = `notes/${ownerId}/failed-metadata-save`;
  const noteId = "8f1592e9-0ac7-4461-a1b0-e67625b5879e";
  let objectDeleted = false;
  let responseStatus;
  process.env.JWT_SECRET = "test-jwt-secret-that-is-long-enough-for-tests";
  Note.findOne = async () => null;
  s3Storage.getNoteRecord = async () => null;
  s3Storage.putNoteRecord = async () => { throw new Error("S3 metadata unavailable"); };
  s3Storage.verifyUploadedObject = async () => true;
  s3Storage.deleteObject = async () => {
    objectDeleted = true;
  };
  const uploadToken = jwt.sign(
    {
      sub: ownerId,
      key,
      noteId,
      fileName: "notes.pdf",
      contentType: "application/pdf",
      fileSize: 9,
      title: "My notes",
      visibility: "public",
      tags: [],
    },
    process.env.JWT_SECRET,
    { expiresIn: 60, issuer: "noteshub-s3-upload", audience: "noteshub-s3-upload" }
  );

  try {
    await completeNoteUpload(
      { user: { id: ownerId }, body: { uploadToken } },
      {
        status(status) {
          responseStatus = status;
          return this;
        },
        json() {
          return this;
        },
      }
    );
  } finally {
    Note.findOne = originals.findOne;
    s3Storage.getNoteRecord = originals.getNoteRecord;
    s3Storage.putNoteRecord = originals.putNoteRecord;
    s3Storage.verifyUploadedObject = originals.verify;
    s3Storage.deleteObject = originals.delete;
    if (originals.jwtSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = originals.jwtSecret;
  }

  assert.equal(responseStatus, 500);
  assert.equal(objectDeleted, true);
});

test("expired upload tokens are rejected before an S3 operation", async () => {
  const originalVerify = s3Storage.verifyUploadedObject;
  const originalJwtSecret = process.env.JWT_SECRET;
  const ownerId = "65aabbccddeeff0011223344";
  let responseStatus;
  process.env.JWT_SECRET = "test-jwt-secret-that-is-long-enough-for-tests";
  s3Storage.verifyUploadedObject = async () => {
    assert.fail("Expired upload token must not access S3");
  };
  const uploadToken = jwt.sign(
    { sub: ownerId, key: `notes/${ownerId}/expired-object` },
    process.env.JWT_SECRET,
    { expiresIn: -1, issuer: "noteshub-s3-upload", audience: "noteshub-s3-upload" }
  );

  try {
    await completeNoteUpload(
      { user: { id: ownerId }, body: { uploadToken } },
      {
        status(status) {
          responseStatus = status;
          return this;
        },
        json() {
          return this;
        },
      }
    );
  } finally {
    s3Storage.verifyUploadedObject = originalVerify;
    if (originalJwtSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = originalJwtSecret;
  }

  assert.equal(responseStatus, 400);
});

test("invalid uploaded content is removed and not saved as a note", async () => {
  const originals = {
    findOne: Note.findOne,
    getNoteRecord: s3Storage.getNoteRecord,
    putNoteRecord: s3Storage.putNoteRecord,
    verify: s3Storage.verifyUploadedObject,
    delete: s3Storage.deleteObject,
    jwtSecret: process.env.JWT_SECRET,
  };
  const ownerId = "65aabbccddeeff0011223344";
  let objectDeleted = false;
  let responseStatus;
  process.env.JWT_SECRET = "test-jwt-secret-that-is-long-enough-for-tests";
  Note.findOne = async () => null;
  s3Storage.getNoteRecord = async () => null;
  s3Storage.putNoteRecord = async () => assert.fail("Invalid file must not create metadata");
  s3Storage.verifyUploadedObject = async () => {
    const error = new Error("Signature does not match");
    error.code = "INVALID_S3_UPLOAD";
    throw error;
  };
  s3Storage.deleteObject = async () => {
    objectDeleted = true;
  };
  const uploadToken = jwt.sign(
    {
      sub: ownerId,
      key: `notes/${ownerId}/invalid-object`,
      noteId: "5fb71276-7c7d-4867-9e45-e0df37d0cac3",
      fileName: "notes.pdf",
      contentType: "application/pdf",
      fileSize: 9,
      title: "My notes",
      visibility: "public",
      tags: [],
    },
    process.env.JWT_SECRET,
    { expiresIn: 60, issuer: "noteshub-s3-upload", audience: "noteshub-s3-upload" }
  );

  try {
    await completeNoteUpload(
      { user: { id: ownerId }, body: { uploadToken } },
      {
        status(status) {
          responseStatus = status;
          return this;
        },
        json() {
          return this;
        },
      }
    );
  } finally {
    Note.findOne = originals.findOne;
    s3Storage.getNoteRecord = originals.getNoteRecord;
    s3Storage.putNoteRecord = originals.putNoteRecord;
    s3Storage.verifyUploadedObject = originals.verify;
    s3Storage.deleteObject = originals.delete;
    if (originals.jwtSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = originals.jwtSecret;
  }

  assert.equal(responseStatus, 400);
  assert.equal(objectDeleted, true);
});

test("upload tokens cannot be completed by another user", async () => {
  const originalVerify = s3Storage.verifyUploadedObject;
  const originalJwtSecret = process.env.JWT_SECRET;
  const ownerId = "65aabbccddeeff0011223344";
  let responseStatus;
  process.env.JWT_SECRET = "test-jwt-secret-that-is-long-enough-for-tests";
  s3Storage.verifyUploadedObject = async () => {
    throw new Error("Must not verify an unauthorized upload");
  };
  const uploadToken = jwt.sign(
    { sub: ownerId, key: `notes/${ownerId}/unique-upload-key` },
    process.env.JWT_SECRET,
    { expiresIn: 60, issuer: "noteshub-s3-upload", audience: "noteshub-s3-upload" }
  );

  try {
    await completeNoteUpload(
      { user: { id: "65aabbccddeeff0011223345" }, body: { uploadToken } },
      {
        status(status) {
          responseStatus = status;
          return this;
        },
        json() {
          return this;
        },
      }
    );
  } finally {
    s3Storage.verifyUploadedObject = originalVerify;
    if (originalJwtSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = originalJwtSecret;
  }

  assert.equal(responseStatus, 400);
});

test("private note downloads are hidden from other users", async () => {
  const originalGetNoteRecord = s3Storage.getNoteRecord;
  const originalCreateDownloadUrl = s3Storage.createDownloadUrl;
  const ownerId = new mongoose.Types.ObjectId();
  let responseStatus;
  let downloadUrlCreated = false;
  s3Storage.getNoteRecord = async () => ({
      s3Key: "notes/private/private-object",
      fileName: "notes.pdf",
      contentType: "application/pdf",
      uploadedBy: ownerId,
      visibility: "private",
      uploadStatus: "active",
  });
  s3Storage.createDownloadUrl = async () => {
    downloadUrlCreated = true;
    return "https://signed-download.example.test";
  };

  try {
    await downloadNoteFile(
      { params: { id: "6addced159123fc5d9b6b585" }, user: { id: new mongoose.Types.ObjectId().toString() } },
      {
        status(status) {
          responseStatus = status;
          return this;
        },
        json() {
          return this;
        },
      }
    );
  } finally {
    s3Storage.getNoteRecord = originalGetNoteRecord;
    s3Storage.createDownloadUrl = originalCreateDownloadUrl;
  }

  assert.equal(responseStatus, 404);
  assert.equal(downloadUrlCreated, false);
});

test("public S3 notes can still be downloaded without signing in", async () => {
  const originalGetNoteRecord = s3Storage.getNoteRecord;
  const originalCreateDownloadUrl = s3Storage.createDownloadUrl;
  let redirectUrl;
  s3Storage.getNoteRecord = async () => ({
      s3Key: "notes/user/public-object",
      fileName: "public notes.pdf",
      contentType: "application/pdf",
      uploadedBy: new mongoose.Types.ObjectId(),
      visibility: "public",
      uploadStatus: "active",
  });
  s3Storage.createDownloadUrl = async () => "https://signed-download.example.test";

  try {
    await downloadNoteFile(
      { params: { id: "6addced159123fc5d9b6b585" } },
      {
        set(name, value) {
          assert.equal(name, "Cache-Control");
          assert.equal(value, "private, no-store");
          return this;
        },
        redirect(status, url) {
          assert.equal(status, 302);
          redirectUrl = url;
          return this;
        },
        status(status) {
          assert.fail(`Unexpected status: ${status}`);
          return this;
        },
      }
    );
  } finally {
    s3Storage.getNoteRecord = originalGetNoteRecord;
    s3Storage.createDownloadUrl = originalCreateDownloadUrl;
  }

  assert.equal(redirectUrl, "https://signed-download.example.test");
});

test("note deletion marks the record before removing the object", async () => {
  const originals = {
    findOne: Note.findOne,
    updateOne: Note.updateOne,
    deleteOne: Note.deleteOne,
    deleteObject: s3Storage.deleteObject,
  };
  const noteId = new mongoose.Types.ObjectId().toString();
  const ownerId = new mongoose.Types.ObjectId().toString();
  const operations = [];
  let responseBody;
  Note.findOne = async () => ({
    _id: noteId,
    uploadedBy: ownerId,
    s3Key: "notes/user/object-key",
    uploadStatus: "active",
    save: async () => {},
  });
  Note.updateOne = async () => {
    operations.push("mark-deleting");
    return { modifiedCount: 1 };
  };
  s3Storage.deleteObject = async () => operations.push("delete-object");
  Note.deleteOne = async () => {
    operations.push("delete-record");
    return { deletedCount: 1 };
  };

  try {
    await deleteMyNote(
      { params: { id: noteId }, user: { id: ownerId } },
      {
        json(body) {
          responseBody = body;
          return this;
        },
        status() {
          return this;
        },
      }
    );
  } finally {
    Note.findOne = originals.findOne;
    Note.updateOne = originals.updateOne;
    Note.deleteOne = originals.deleteOne;
    s3Storage.deleteObject = originals.deleteObject;
  }

  assert.deepEqual(operations, ["mark-deleting", "delete-object", "delete-record"]);
  assert.equal(responseBody.success, true);
});

test("failed S3 deletion leaves the note marked for a safe retry", async () => {
  const originals = {
    findOne: Note.findOne,
    updateOne: Note.updateOne,
    deleteObject: s3Storage.deleteObject,
  };
  const ownerId = new mongoose.Types.ObjectId().toString();
  let uploadStatus;
  let responseStatus;
  Note.findOne = async () => ({
    _id: "4f4152a7-45bc-4c73-b2d0-468c8bc3c5a1",
    uploadedBy: ownerId,
    s3Key: "notes/user/object-key",
    uploadStatus: "active",
    save: async () => {},
  });
  Note.updateOne = async (filter, update) => {
    uploadStatus = update.$set.uploadStatus;
    return { modifiedCount: 1 };
  };
  s3Storage.deleteObject = async () => {
    throw new Error("S3 unavailable");
  };
  try {
    await deleteMyNote(
      { params: { id: "4f4152a7-45bc-4c73-b2d0-468c8bc3c5a1" }, user: { id: ownerId } },
      {
        status(status) {
          responseStatus = status;
          return this;
        },
        json() {
          return this;
        },
      }
    );
  } finally {
    Note.findOne = originals.findOne;
    Note.updateOne = originals.updateOne;
    s3Storage.deleteObject = originals.deleteObject;
  }

  assert.equal(responseStatus, 500);
  assert.equal(uploadStatus, "deleting");
});

test("profile photo uploads store the image in S3 and keep the object key on the user", async () => {
  const originalFindById = User.findById;
  const originalPutProfilePhoto = s3Storage.putProfilePhoto;
  const userId = new mongoose.Types.ObjectId();
  let uploadedPhoto;
  let responseBody;
  const photoMetadata = {
    bucket: "notes-test-bucket",
    etag: '"photo-etag"',
    fileSize: 8,
  };
  const user = {
    _id: userId,
    id: userId.toString(),
    name: "Jane Doe",
    user_id: "9876543210",
    async save() {},
  };
  User.findById = async () => user;
  s3Storage.putProfilePhoto = async (photo) => {
    uploadedPhoto = photo;
    return photoMetadata;
  };

  try {
    await updateProfilePhoto(
      {
        user: { id: userId.toString() },
        file: {
          mimetype: "image/png",
          buffer: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
        },
      },
      { json(body) { responseBody = body; return this; } }
    );
  } finally {
    User.findById = originalFindById;
    s3Storage.putProfilePhoto = originalPutProfilePhoto;
  }

  assert.equal(uploadedPhoto.key, "photos/jane-doe-9876543210");
  assert.equal(uploadedPhoto.contentType, "image/png");
  assert.equal(uploadedPhoto.body.length, 8);
  assert.equal(user.profilePhotoS3Key, uploadedPhoto.key);
  assert.equal(user.profilePhotoContentType, "image/png");
  assert.equal(user.profilePhotoFileId, undefined);
  assert.deepEqual(user.profilePhotoS3Metadata, photoMetadata);
  assert.equal(responseBody.profilePhotoUrl, "/api/auth/profile/photo");
});

test("legacy GridFS profile photos migrate to S3 when requested", async () => {
  const originalFindById = User.findById;
  const originalGridFSBucket = Object.getOwnPropertyDescriptor(mongoose.mongo, "GridFSBucket");
  const originalPutProfilePhoto = s3Storage.putProfilePhoto;
  const originalCreateProfilePhotoUrl = s3Storage.createProfilePhotoUrl;
  const userId = new mongoose.Types.ObjectId();
  const fileId = new mongoose.Types.ObjectId();
  const image = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const user = {
    _id: userId,
    name: "Jane Doe",
    user_id: "9876543210",
    profilePhotoFileId: fileId,
    profilePhotoContentType: "image/png",
    async save() {},
  };
  let uploadedPhoto;
  let deletedFileId;
  let redirectUrl;
  class MockGridFSBucket {
    openDownloadStream(id) {
      assert.equal(id, fileId);
      return Readable.from([image]);
    }

    async delete(id) {
      deletedFileId = id;
    }
  }
  Object.defineProperty(mongoose.mongo, "GridFSBucket", {
    configurable: true,
    value: MockGridFSBucket,
  });
  User.findById = () => ({ select: async () => user });
  s3Storage.putProfilePhoto = async (photo) => { uploadedPhoto = photo; };
  s3Storage.createProfilePhotoUrl = async ({ key }) => `https://s3.example.test/${key}`;

  try {
    await getProfilePhoto(
      { user: { id: userId.toString() } },
      {
        setHeader() {},
        redirect(_status, url) {
          redirectUrl = url;
          return this;
        },
      }
    );
  } finally {
    Object.defineProperty(mongoose.mongo, "GridFSBucket", originalGridFSBucket);
    User.findById = originalFindById;
    s3Storage.putProfilePhoto = originalPutProfilePhoto;
    s3Storage.createProfilePhotoUrl = originalCreateProfilePhotoUrl;
  }

  assert.deepEqual(uploadedPhoto, {
    key: "photos/jane-doe-9876543210",
    body: image,
    contentType: "image/png",
  });
  assert.equal(user.profilePhotoS3Key, uploadedPhoto.key);
  assert.equal(user.profilePhotoFileId, undefined);
  assert.equal(deletedFileId, fileId);
  assert.equal(redirectUrl, `https://s3.example.test/${uploadedPhoto.key}`);
});

test("legacy profile-photo S3 objects move to photos when requested", async () => {
  const originalFindById = User.findById;
  const originals = {
    getProfilePhoto: s3Storage.getProfilePhoto,
    putProfilePhoto: s3Storage.putProfilePhoto,
    createProfilePhotoUrl: s3Storage.createProfilePhotoUrl,
    deleteObject: s3Storage.deleteObject,
  };
  const userId = new mongoose.Types.ObjectId();
  const image = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const user = {
    _id: userId,
    name: "Jane Doe",
    user_id: "9876543210",
    profilePhotoS3Key: "profile-photo/jane-doe-9876543210",
    profilePhotoContentType: "image/png",
    async save() {},
  };
  let uploadedPhoto;
  let deletedKey;
  let redirectUrl;
  User.findById = () => ({ select: async () => user });
  s3Storage.getProfilePhoto = async ({ key }) => {
    assert.equal(key, "profile-photo/jane-doe-9876543210");
    return { body: image, contentType: "image/png" };
  };
  s3Storage.putProfilePhoto = async (photo) => { uploadedPhoto = photo; };
  s3Storage.createProfilePhotoUrl = async ({ key }) => `https://s3.example.test/${key}`;
  s3Storage.deleteObject = async (key) => { deletedKey = key; };

  try {
    await getProfilePhoto(
      { user: { id: userId.toString() } },
      {
        setHeader() {},
        redirect(_status, url) {
          redirectUrl = url;
          return this;
        },
      }
    );
  } finally {
    User.findById = originalFindById;
    for (const [name, original] of Object.entries(originals)) {
      s3Storage[name] = original;
    }
  }

  assert.deepEqual(uploadedPhoto, {
    key: "photos/jane-doe-9876543210",
    body: image,
    contentType: "image/png",
  });
  assert.equal(user.profilePhotoS3Key, uploadedPhoto.key);
  assert.equal(deletedKey, "profile-photo/jane-doe-9876543210");
  assert.equal(redirectUrl, `https://s3.example.test/${uploadedPhoto.key}`);
});

test("profile edits store the uploaded photo in S3", async () => {
  const originalFindById = User.findById;
  const originalFindOne = User.findOne;
  const originalPutProfilePhoto = s3Storage.putProfilePhoto;
  const ownerId = new mongoose.Types.ObjectId();
  const user = {
    _id: ownerId,
    id: ownerId.toString(),
    name: "Jane Doe",
    user_id: "9876543210",
    async save() {},
  };
  let uploadedPhoto;
  User.findById = async () => user;
  User.findOne = async () => null;
  s3Storage.putProfilePhoto = async (photo) => { uploadedPhoto = photo; };

  try {
    await updateProfile(
      {
        user: { id: ownerId.toString() },
        body: {
          name: "Test User",
          email: "test@example.com",
          university: "Example University",
          course: "Engineering",
          year: "2026",
        },
        file: {
          mimetype: "image/png",
          buffer: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
        },
      },
      { json() { return this; } }
    );
  } finally {
    User.findById = originalFindById;
    User.findOne = originalFindOne;
    s3Storage.putProfilePhoto = originalPutProfilePhoto;
  }

  assert.equal(uploadedPhoto.key, "photos/test-user-9876543210");
  assert.equal(user.profilePhotoS3Key, uploadedPhoto.key);
  assert.equal(user.profilePhotoContentType, "image/png");
  assert.equal(user.profilePhotoFileId, undefined);
});

test("profile photo endpoint redirects to a short-lived S3 URL", async () => {
  const originalFindById = User.findById;
  const originalCreateProfilePhotoUrl = s3Storage.createProfilePhotoUrl;
  const key = "photos/jane-doe-9876543210";
  let redirectStatus;
  let redirectUrl;
  User.findById = () => ({
    select: async () => ({
      profilePhotoS3Key: key,
      profilePhotoContentType: "image/png",
    }),
  });
  s3Storage.createProfilePhotoUrl = async (photo) => {
    assert.deepEqual(photo, { key, contentType: "image/png" });
    return "https://s3.example.test/signed-photo";
  };

  try {
    await getProfilePhoto(
      { user: { id: new mongoose.Types.ObjectId().toString() } },
      {
        headers: {},
        setHeader(name, value) {
          this.headers[name] = value;
        },
        redirect(status, url) {
          redirectStatus = status;
          redirectUrl = url;
          return this;
        },
      }
    );
  } finally {
    User.findById = originalFindById;
    s3Storage.createProfilePhotoUrl = originalCreateProfilePhotoUrl;
  }

  assert.equal(redirectStatus, 302);
  assert.equal(redirectUrl, "https://s3.example.test/signed-photo");
});

test("registration stores a hash and only returns a generic success message", async () => {
  const originalFindOne = User.findOne;
  const originalCreate = User.create;
  const originalSecret = process.env.JWT_SECRET;
  const jwtSecret = randomBytes(32).toString("hex");
  const submittedPassword = "safe-test-password";
  const userId = new mongoose.Types.ObjectId();
  let createdUser;
  let responseBody;
  let cookieOptions;
  let token;
  const response = {
    cookie(_name, value, options) {
      token = value;
      cookieOptions = options;
      return this;
    },
    status(status) {
      this.statusCode = status;
      return this;
    },
    json(body) {
      responseBody = body;
      return this;
    },
  };

  User.findOne = async () => null;
  User.create = async (user) => {
    createdUser = user;
    return { ...user, _id: userId };
  };
  process.env.JWT_SECRET = jwtSecret;

  try {
    await registerUser(
      {
        body: {
          name: "Test User",
          email: "test@example.com",
          password: submittedPassword,
          university: "Example University",
          course: "Engineering",
          year: "2026",
        },
      },
      response
    );
  } finally {
    User.findOne = originalFindOne;
    User.create = originalCreate;
    if (originalSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = originalSecret;
  }

  assert.equal(response.statusCode, 201);
  assert.match(createdUser.user_id, /^\d{10}$/);
  assert.equal(createdUser.name, "Test User");
  assert.equal(createdUser.email, "test@example.com");
  assert.equal(createdUser.university, "Example University");
  assert.equal(createdUser.course, "Engineering");
  assert.equal(createdUser.year, "2026");
  assert.equal(createdUser.role, "USER");
  assert.equal(createdUser.notesIndexInitialized, true);
  assert.equal(await bcrypt.compare(submittedPassword, createdUser.password), true);
  assert.notEqual(createdUser.password, submittedPassword);
  assert.equal(jwt.verify(token, jwtSecret).id, userId.toString());
  assert.equal(jwt.verify(token, jwtSecret).user_id, createdUser.user_id);
  assert.equal(cookieOptions.httpOnly, true);
  assert.equal("password" in responseBody, false);
  assert.equal("token" in responseBody, false);
  assert.equal(JSON.stringify(responseBody).includes(submittedPassword), false);
});

test("admin APIs require an active ADMIN role from the database", async () => {
  const originalFindById = User.findById;
  const originalSecret = process.env.JWT_SECRET;
  const jwtSecret = randomBytes(32).toString("hex");
  const accountId = new mongoose.Types.ObjectId();
  const app = express();
  app.use(cookieParser());
  app.use("/api/admin", adminRoutes);
  const server = app.listen(0, "127.0.0.1");
  process.env.JWT_SECRET = jwtSecret;

  const tokenFor = (userId) => jwt.sign(
    { id: accountId, user_id: userId },
    jwtSecret,
    { expiresIn: 3600, algorithm: "HS256" }
  );
  const request = async (token) => fetch(
    `http://127.0.0.1:${server.address().port}/api/admin/auth/verify`,
    token ? { headers: { cookie: `token=${token}` } } : undefined
  );

  try {
    await new Promise((resolve) => server.once("listening", resolve));
    const unauthenticated = await request();
    assert.equal(unauthenticated.status, 401);

    let account = { _id: accountId, role: "USER", accountStatus: "active", deletedAt: null };
    User.findById = () => ({ select: async () => account });
    const ordinaryUser = await request(tokenFor("1234567890"));
    assert.equal(ordinaryUser.status, 403);

    account = { ...account, role: "ADMIN", accountStatus: "suspended" };
    const suspendedAdmin = await request(tokenFor("1234567890"));
    assert.equal(suspendedAdmin.status, 403);

    account = { ...account, accountStatus: "active" };
    const activeAdmin = await request(tokenFor("1234567890"));
    assert.equal(activeAdmin.status, 200);
    const response = await activeAdmin.json();
    assert.equal(response.isAuthenticated, true);
    assert.equal(response.admin.role, "ADMIN");
    assert.equal("token" in response, false);
  } finally {
    User.findById = originalFindById;
    if (originalSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = originalSecret;
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
});

test("login assigns and saves a user ID for an existing account", async () => {
  const originalFindOne = User.findOne;
  const originalSecret = process.env.JWT_SECRET;
  const jwtSecret = randomBytes(32).toString("hex");
  const ownerId = new mongoose.Types.ObjectId();
  const password = "existing-user-password";
  const user = {
    _id: ownerId,
    password: await bcrypt.hash(password, 4),
    async save() {
      this.saved = true;
    },
  };
  let token;
  User.findOne = () => ({
    select: async () => user,
  });
  process.env.JWT_SECRET = jwtSecret;

  try {
    await loginUser(
      { body: { email: "existing@example.com", password } },
      {
        cookie(_name, value) {
          token = value;
          return this;
        },
        json() {
          return this;
        },
      }
    );
  } finally {
    User.findOne = originalFindOne;
    if (originalSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = originalSecret;
  }

  assert.equal(user.saved, true);
  assert.match(user.user_id, /^\d{10}$/);
  assert.equal(jwt.verify(token, jwtSecret).user_id, user.user_id);
});

test("incorrect passwords receive a generic response without account details", async () => {
  const originalFindOne = User.findOne;
  let responseBody;
  let responseStatus;
  const response = {
    status(status) {
      responseStatus = status;
      return this;
    },
    json(body) {
      responseBody = body;
      return this;
    },
  };
  User.findOne = () => ({
    select: async () => ({
      password: await bcrypt.hash("correct-test-password", 4),
      _id: "test-user-id",
    }),
  });

  try {
    await loginUser(
      { body: { email: "private@example.com", password: "wrong-test-password" } },
      response
    );
  } finally {
    User.findOne = originalFindOne;
  }

  assert.equal(responseStatus, 401);
  assert.deepEqual(responseBody, { message: "Invalid email or password" });
  assert.equal(JSON.stringify(responseBody).includes("private@example.com"), false);
  assert.equal(JSON.stringify(responseBody).includes("wrong-test-password"), false);
});

test("authenticated password changes verify the current password and clear the session", async () => {
  const originalFindById = User.findById;
  const originalSecret = process.env.JWT_SECRET;
  const currentPassword = "current-test-password";
  const user = {
    password: await bcrypt.hash(currentPassword, 4),
    async save() {},
  };
  let responseBody;
  let clearedCookie = false;
  const response = {
    clearCookie(name) {
      clearedCookie = name === "token";
      return this;
    },
    json(body) {
      responseBody = body;
      return this;
    },
  };
  User.findById = () => ({
    select: async () => user,
  });

  process.env.JWT_SECRET = randomBytes(32).toString("hex");

  try {
    await changePassword(
      {
        user: { id: "authenticated-user-id" },
        body: { currentPassword, newPassword: "new-safe-test-password" },
      },
      response
    );
  } finally {
    User.findById = originalFindById;
    if (originalSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = originalSecret;
  }

  assert.equal(await bcrypt.compare("new-safe-test-password", user.password), true);
  assert.equal(clearedCookie, true);
  assert.equal("password" in responseBody, false);
  assert.equal("token" in responseBody, false);
});

test("incorrect current password does not change the stored password", async () => {
  const originalFindById = User.findById;
  const oldHash = await bcrypt.hash("actual-current-password", 4);
  const user = {
    password: oldHash,
    async save() {
      assert.fail("password must not be saved when the current password is wrong");
    },
  };
  let responseStatus;
  let responseBody;
  const response = {
    status(status) {
      responseStatus = status;
      return this;
    },
    json(body) {
      responseBody = body;
      return this;
    },
  };
  User.findById = () => ({ select: async () => user });

  try {
    await changePassword(
      {
        user: { id: "authenticated-user-id" },
        body: { currentPassword: "incorrect-current-password", newPassword: "new-safe-password" },
      },
      response
    );
  } finally {
    User.findById = originalFindById;
  }

  assert.equal(responseStatus, 401);
  assert.deepEqual(responseBody, { message: "Current password is incorrect." });
  assert.equal(user.password, oldHash);
});

test("validation responses never echo submitted credentials", async () => {
  const app = express();
  app.use(express.json());
  app.use("/api/auth", authRoutes);
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));

  try {
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const response = await fetch(`http://127.0.0.1:${address.port}/api/auth/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        email: "private@example.com",
        password: "s",
      }),
    });
    const responseBody = await response.text();

    assert.equal(response.status, 400);
    assert.equal(responseBody.includes("private@example.com"), false);
    assert.equal(responseBody.includes('"s"'), false);
    assert.equal(responseBody.includes('"value"'), false);
  } finally {
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
});
