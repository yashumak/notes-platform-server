import assert from "node:assert/strict";
import bcrypt from "bcryptjs";
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
import {
  completeNoteUpload,
  createNoteUploadUrl,
  deleteMyNote,
  downloadNoteFile,
  getNoteStats,
  listNotes,
} from "../controllers/notes.controller.js";
import { protect } from "../middlewares/authMiddleware.js";
import { hasValidFileSignature, validateFileMetadata } from "../utils/fileValidation.js";
import {
  changePassword,
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
import { ensureUserId, generateUserId } from "../utils/userId.js";
import { isPublicNotesReadRequest } from "../utils/rateLimitPolicy.js";
import { decryptAuthPayload, getAuthPayloadPublicKey } from "../utils/authPayloadEncryption.js";
import { s3Storage, UPLOAD_URL_TTL_SECONDS } from "../services/s3Storage.js";

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

test("public notes reads use a separate rate-limit bucket from other API requests", () => {
  assert.equal(isPublicNotesReadRequest({ method: "GET", path: "/api/notes" }), true);
  assert.equal(isPublicNotesReadRequest({ method: "GET", path: "/api/notes/stats" }), true);
  assert.equal(isPublicNotesReadRequest({ method: "POST", path: "/api/notes" }), false);
  assert.equal(isPublicNotesReadRequest({ method: "GET", path: "/api/notes/123/file" }), false);
  assert.equal(isPublicNotesReadRequest({ method: "GET", path: "/api/auth/verify" }), false);
});

test("upload APIs require authentication while shared note reads remain public", () => {
  const routes = authRoutes.stack
    .map((layer) => layer.route)
    .filter(Boolean);
  const changePasswordRoute = routes.find((route) => route.path === "/change-password");

  assert.ok(changePasswordRoute);
  assert.ok(changePasswordRoute.stack.some((layer) => layer.handle === protect));
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

test("session verification returns the authenticated user ID for private cache isolation", async () => {
  const originalFindById = User.findById;
  const user = {
    id: "private-user-id",
    _id: "private-user-id",
    user_id: "1234567890",
    name: "Test User",
    email: "test@example.com",
    university: "Example University",
    course: "Engineering",
    year: "1st Year",
    profilePhotoFileId: null,
  };
  let responseBody;
  User.findById = () => ({ select: async () => user });

  try {
    await verifyUser(
      { user: { id: user.id, iat: 1, exp: Math.floor(Date.now() / 1000) + 3600 } },
      { json: (body) => { responseBody = body; } }
    );
  } finally {
    User.findById = originalFindById;
  }

  assert.equal(responseBody.user.email, user.email);
  assert.equal(responseBody.user.id, user.user_id);
});

test("session verification migrates an existing GridFS profile photo to S3", async () => {
  const originalFindById = User.findById;
  const originalGridFSBucket = Object.getOwnPropertyDescriptor(mongoose.mongo, "GridFSBucket");
  const originals = {
    putProfilePhoto: s3Storage.putProfilePhoto,
    createProfilePhotoUrl: s3Storage.createProfilePhotoUrl,
  };
  const userId = new mongoose.Types.ObjectId();
  const fileId = new mongoose.Types.ObjectId();
  const image = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const user = {
    _id: userId,
    id: userId.toString(),
    name: "Jane Doe",
    user_id: "9876543210",
    email: "jane@example.test",
    university: "Example University",
    course: "Engineering",
    year: "2026",
    profilePhotoFileId: fileId,
    profilePhotoContentType: "image/png",
    async save() {},
  };
  let uploadedPhoto;
  let responseBody;
  class MockGridFSBucket {
    openDownloadStream(id) {
      assert.equal(id, fileId);
      return Readable.from([image]);
    }

    async delete() {}
  }
  Object.defineProperty(mongoose.mongo, "GridFSBucket", {
    configurable: true,
    value: MockGridFSBucket,
  });
  User.findById = () => ({ select: async () => user });
  s3Storage.putProfilePhoto = async (photo) => { uploadedPhoto = photo; };
  s3Storage.createProfilePhotoUrl = async () => "https://s3.example.test/photo";

  try {
    await verifyUser(
      { user: { id: user.id, iat: 1, exp: Math.floor(Date.now() / 1000) + 3600 } },
      { json: (body) => { responseBody = body; } }
    );
  } finally {
    Object.defineProperty(mongoose.mongo, "GridFSBucket", originalGridFSBucket);
    User.findById = originalFindById;
    s3Storage.putProfilePhoto = originals.putProfilePhoto;
    s3Storage.createProfilePhotoUrl = originals.createProfilePhotoUrl;
  }

  assert.equal(uploadedPhoto.key, "photos/jane-doe-9876543210");
  assert.equal(user.profilePhotoFileId, undefined);
  assert.equal(user.profilePhotoS3Key, uploadedPhoto.key);
  assert.equal(responseBody.user.profilePhotoUrl, `/api/auth/profile/photo?v=${encodeURIComponent(uploadedPhoto.key)}`);
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
  process.env.AWS_REGION = "ap-south-1";
  process.env.AWS_S3_BUCKET = "notes-test-bucket";
  process.env.AWS_ACCESS_KEY_ID = "test-access-key";
  process.env.AWS_SECRET_ACCESS_KEY = "test-secret-key";
  S3Client.prototype.send = async (command) => { uploadedCommand = command; };

  try {
    await s3Storage.putProfilePhoto({
      key: "photos/jane-doe-1234567890",
      body: image,
      contentType: "image/png",
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
});

test("new note records use the root metadata prefix", async () => {
  const savedEnvironment = {
    AWS_REGION: process.env.AWS_REGION,
    AWS_S3_BUCKET: process.env.AWS_S3_BUCKET,
    AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
  };
  const originalSend = S3Client.prototype.send;
  let uploadedCommand;
  process.env.AWS_REGION = "ap-south-1";
  process.env.AWS_S3_BUCKET = "notes-test-bucket";
  process.env.AWS_ACCESS_KEY_ID = "test-access-key";
  process.env.AWS_SECRET_ACCESS_KEY = "test-secret-key";
  S3Client.prototype.send = async (command) => { uploadedCommand = command; };

  try {
    await s3Storage.putNoteRecord({ _id: "course-notes-1234567890" });
  } finally {
    S3Client.prototype.send = originalSend;
    for (const [name, value] of Object.entries(savedEnvironment)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }

  assert.ok(uploadedCommand instanceof PutObjectCommand);
  assert.equal(uploadedCommand.input.Key, "metadata/course-notes-1234567890.json");
});

test("note records list from current and legacy metadata prefixes", async () => {
  const savedEnvironment = {
    AWS_REGION: process.env.AWS_REGION,
    AWS_S3_BUCKET: process.env.AWS_S3_BUCKET,
    AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
  };
  const originalSend = S3Client.prototype.send;
  const currentId = "imported notes 2024";
  const legacyId = "4f4152a7-45bc-4c73-b2d0-468c8bc3c5a1";
  const listedPrefixes = [];
  const fetchedKeys = [];
  process.env.AWS_REGION = "ap-south-1";
  process.env.AWS_S3_BUCKET = "notes-test-bucket";
  process.env.AWS_ACCESS_KEY_ID = "test-access-key";
  process.env.AWS_SECRET_ACCESS_KEY = "test-secret-key";
  S3Client.prototype.send = async (command) => {
    if (command instanceof ListObjectsV2Command) {
      listedPrefixes.push(command.input.Prefix);
      return {
        Contents: command.input.Prefix === "metadata/"
          ? [{ Key: `metadata/${currentId}.json` }]
          : [{ Key: `notes/metadata/${legacyId}.json` }],
      };
    }
    if (command instanceof GetObjectCommand) {
      fetchedKeys.push(command.input.Key);
      if (command.input.Key === `metadata/${legacyId}.json`) {
        const error = new Error("Not found");
        error.name = "NoSuchKey";
        throw error;
      }
      const isLegacy = command.input.Key === `notes/metadata/${legacyId}.json`;
      return {
        Body: {
          transformToString: async () => JSON.stringify({
            _id: isLegacy ? legacyId : currentId,
            title: isLegacy ? "Legacy" : "Current",
          }),
        },
      };
    }
    throw new Error("Unexpected S3 command");
  };

  try {
    const records = await s3Storage.listNoteRecords();
    assert.deepEqual(records.map(({ title }) => title), ["Current", "Legacy"]);
  } finally {
    S3Client.prototype.send = originalSend;
    for (const [name, value] of Object.entries(savedEnvironment)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }

  assert.deepEqual(listedPrefixes, ["metadata/", "notes/metadata/"]);
  assert.ok(fetchedKeys.includes(`metadata/${legacyId}.json`));
  assert.ok(fetchedKeys.includes(`notes/metadata/${legacyId}.json`));
});

test("S3 note page reads only the requested metadata records", async () => {
  const savedEnvironment = {
    AWS_REGION: process.env.AWS_REGION,
    AWS_S3_BUCKET: process.env.AWS_S3_BUCKET,
    AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
  };
  const originalSend = S3Client.prototype.send;
  const ids = Array.from({ length: 75 }, (_, index) => `paged-note-${index}`);
  const fetchedIds = [];
  process.env.AWS_REGION = "ap-south-1";
  process.env.AWS_S3_BUCKET = "notes-test-bucket";
  process.env.AWS_ACCESS_KEY_ID = "test-access-key";
  process.env.AWS_SECRET_ACCESS_KEY = "test-secret-key";
  S3Client.prototype.send = async (command) => {
    if (command instanceof ListObjectsV2Command) {
      return {
        Contents: command.input.Prefix === "metadata/"
          ? ids.map((id, index) => ({
              Key: `metadata/${id}.json`,
              LastModified: new Date(2026, 0, index + 1),
            }))
          : [],
      };
    }
    if (command instanceof GetObjectCommand) {
      const id = command.input.Key.slice("metadata/".length, -".json".length);
      fetchedIds.push(id);
      return {
        Body: {
          transformToString: async () => JSON.stringify({ _id: id, title: id }),
        },
      };
    }
    throw new Error("Unexpected S3 command");
  };

  try {
    const result = await s3Storage.listNoteRecordPage({ offset: 30, limit: 30 });
    assert.equal(result.total, 75);
    assert.equal(result.records.length, 30);
    assert.equal(fetchedIds.length, 30);
    assert.equal(result.records[0]._id, "paged-note-44");
    assert.equal(result.records[29]._id, "paged-note-15");
  } finally {
    S3Client.prototype.send = originalSend;
    for (const [name, value] of Object.entries(savedEnvironment)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});

test("note records are fetched concurrently with a bounded number of S3 requests", async () => {
  const savedEnvironment = {
    AWS_REGION: process.env.AWS_REGION,
    AWS_S3_BUCKET: process.env.AWS_S3_BUCKET,
    AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
  };
  const originalSend = S3Client.prototype.send;
  const ids = Array.from({ length: 30 }, (_, index) => `note-${index}`);
  let activeRequests = 0;
  let maxConcurrentRequests = 0;
  process.env.AWS_REGION = "ap-south-1";
  process.env.AWS_S3_BUCKET = "notes-test-bucket";
  process.env.AWS_ACCESS_KEY_ID = "test-access-key";
  process.env.AWS_SECRET_ACCESS_KEY = "test-secret-key";
  S3Client.prototype.send = async (command) => {
    if (command instanceof ListObjectsV2Command) {
      return {
        Contents: command.input.Prefix === "metadata/"
          ? ids.map((id) => ({ Key: `metadata/${id}.json` }))
          : [],
      };
    }
    if (command instanceof GetObjectCommand) {
      activeRequests += 1;
      maxConcurrentRequests = Math.max(maxConcurrentRequests, activeRequests);
      await new Promise((resolve) => setTimeout(resolve, 1));
      activeRequests -= 1;
      return {
        Body: {
          transformToString: async () => JSON.stringify({ _id: command.input.Key }),
        },
      };
    }
    throw new Error("Unexpected S3 command");
  };

  try {
    const records = await s3Storage.listNoteRecords();
    assert.equal(records.length, ids.length);
    assert.ok(maxConcurrentRequests > 1);
    assert.ok(maxConcurrentRequests <= 25);
  } finally {
    S3Client.prototype.send = originalSend;
    for (const [name, value] of Object.entries(savedEnvironment)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
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
    assert.equal(
      await s3Storage.verifyUploadedObject({
        key: "notes/test-user/document",
        contentType: "application/pdf",
        fileSize: 9,
      }),
      true
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

test("upload validation checks extension, MIME type, size, and file signature", () => {
  assert.equal(
    validateFileMetadata({
      fileName: "../../notes.pdf",
      contentType: "application/pdf",
      fileSize: 10,
    }).safeName,
    "notes.pdf"
  );
  assert.equal(
    validateFileMetadata({
      fileName: "notes.pdf",
      contentType: "image/png",
      fileSize: 10,
    }).valid,
    false
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

test("upload completion stores private note metadata in S3 without creating a MongoDB note", async () => {
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
  s3Storage.verifyUploadedObject = async (object) => verified.push(object);
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

test("S3 note deletion marks the record before removing the object", async () => {
  const originals = {
    getNoteRecord: s3Storage.getNoteRecord,
    putNoteRecord: s3Storage.putNoteRecord,
    deleteObject: s3Storage.deleteObject,
    deleteNoteRecord: s3Storage.deleteNoteRecord,
  };
  const noteId = "b9c84b91-d865-42e5-bd2f-2030d9663209";
  const ownerId = new mongoose.Types.ObjectId().toString();
  const operations = [];
  let responseBody;
  s3Storage.getNoteRecord = async () => ({
    _id: noteId,
    uploadedBy: ownerId,
    s3Key: "notes/user/object-key",
    uploadStatus: "active",
  });
  s3Storage.putNoteRecord = async (note) => {
    assert.equal(note.uploadStatus, "deleting");
    operations.push("mark-deleting");
  };
  s3Storage.deleteObject = async () => operations.push("delete-object");
  s3Storage.deleteNoteRecord = async () => operations.push("delete-record");

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
    s3Storage.getNoteRecord = originals.getNoteRecord;
    s3Storage.putNoteRecord = originals.putNoteRecord;
    s3Storage.deleteObject = originals.deleteObject;
    s3Storage.deleteNoteRecord = originals.deleteNoteRecord;
  }

  assert.deepEqual(operations, ["mark-deleting", "delete-object", "delete-record"]);
  assert.equal(responseBody.success, true);
});

test("failed S3 deletion leaves the note marked for a safe retry", async () => {
  const originals = {
    getNoteRecord: s3Storage.getNoteRecord,
    putNoteRecord: s3Storage.putNoteRecord,
    deleteObject: s3Storage.deleteObject,
  };
  const ownerId = new mongoose.Types.ObjectId().toString();
  let uploadStatus;
  let responseStatus;
  s3Storage.getNoteRecord = async () => ({
    _id: "4f4152a7-45bc-4c73-b2d0-468c8bc3c5a1",
    uploadedBy: ownerId,
    s3Key: "notes/user/object-key",
    uploadStatus: "active",
  });
  s3Storage.putNoteRecord = async (note) => {
    uploadStatus = note.uploadStatus;
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
    s3Storage.getNoteRecord = originals.getNoteRecord;
    s3Storage.putNoteRecord = originals.putNoteRecord;
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
  const user = {
    _id: userId,
    id: userId.toString(),
    name: "Jane Doe",
    user_id: "9876543210",
    async save() {},
  };
  User.findById = async () => user;
  s3Storage.putProfilePhoto = async (photo) => { uploadedPhoto = photo; };

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
  assert.equal(responseBody.profilePhotoUrl, `/api/auth/profile/photo?v=${encodeURIComponent(uploadedPhoto.key)}`);
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
  assert.equal(await bcrypt.compare(submittedPassword, createdUser.password), true);
  assert.notEqual(createdUser.password, submittedPassword);
  assert.equal(jwt.verify(token, jwtSecret).id, userId.toString());
  assert.equal(jwt.verify(token, jwtSecret).user_id, createdUser.user_id);
  assert.equal(cookieOptions.httpOnly, true);
  assert.equal("password" in responseBody, false);
  assert.equal("token" in responseBody, false);
  assert.equal(JSON.stringify(responseBody).includes(submittedPassword), false);
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
