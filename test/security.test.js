import assert from "node:assert/strict";
import bcrypt from "bcryptjs";
import { EventEmitter } from "node:events";
import express from "express";
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
import { deleteMyNote, getNoteStats, listNotes, uploadNote } from "../controllers/notes.controller.js";
import { protect } from "../middlewares/authMiddleware.js";
import { hasValidFileSignature } from "../utils/fileValidation.js";
import {
  changePassword,
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

test("password changes require authentication and public notes are readable without login", () => {
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
  for (const path of ["/", "/:id/file"]) {
    const route = noteRoutes.find((candidate) => candidate.path === path);
    assert.ok(route, `${path} note route should exist`);
    assert.equal(route.stack.some((layer) => layer.handle === protect), false, `${path} should be public`);
  }
  for (const path of ["/upload", "/mine", "/:id"]) {
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

test("session verification returns profile fields without exposing the user ID", async () => {
  const originalFindById = User.findById;
  const user = {
    id: "private-user-id",
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
  assert.equal("id" in responseBody.user, false);
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

  Note.find = () => ({
    sort() {
      return this;
    },
    select() {
      return Promise.resolve([publicNote]);
    },
  });

  try {
    await listNotes({}, response);
  } finally {
    Note.find = originalFind;
  }

  assert.equal(responseBody.success, true);
  assert.equal(responseBody.notes.length, 1);
  assert.equal(responseBody.notes[0].title, "Shared notes");
  assert.equal(responseBody.notes[0].fileUrl, "/api/notes/note-id/file");
  for (const privateField of ["fileId", "contentType", "uploadedBy", "__v"]) {
    assert.equal(privateField in responseBody.notes[0], false);
  }
});

test("unauthenticated requests can load the public notes list", async () => {
  const originalFind = Note.find;
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
    select: async () => [publicNote],
  });

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
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
});

test("public note statistics return counts only", async () => {
  const originalCountDocuments = Note.countDocuments;
  const originalDistinct = Note.distinct;
  let responseBody;
  Note.countDocuments = async () => 3;
  Note.distinct = async (field) =>
    field === "university"
      ? ["Example University", "", null]
      : ["Notes", "Assignments"];

  try {
    await getNoteStats({}, { json: (body) => { responseBody = body; } });
  } finally {
    Note.countDocuments = originalCountDocuments;
    Note.distinct = originalDistinct;
  }

  assert.deepEqual(responseBody, {
    success: true,
    stats: { total: 3, universities: 1, studyTypes: 2 },
  });
  assert.equal("notes" in responseBody, false);
});

test("note deletion is scoped to the authenticated owner", async () => {
  const originalFindOne = Note.findOne;
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
  }

  assert.equal(query.uploadedBy, authenticatedUserId);
  assert.equal(responseStatus, 404);
});

test("note uploads store the authenticated user ID on the note and top-level GridFS file", async () => {
  const originalGridFSBucket = Object.getOwnPropertyDescriptor(mongoose.mongo, "GridFSBucket");
  const originalDb = mongoose.connection.db;
  const originalCreate = Note.create;
  const originalFindById = User.findById;
  const ownerId = new mongoose.Types.ObjectId();
  const userId = "1234567890";
  const fileId = new mongoose.Types.ObjectId();
  let gridFsOptions;
  let gridFsFileUpdate;
  let createdNote;
  let responseBody;
  const user = {
    _id: ownerId,
    user_id: userId,
  };
  class MockGridFSBucket {
    openUploadStream(_filename, options) {
      gridFsOptions = options;
      const stream = new EventEmitter();
      stream.id = fileId;
      stream.end = () => process.nextTick(() => stream.emit("finish"));
      return stream;
    }
  }
  Object.defineProperty(mongoose.mongo, "GridFSBucket", {
    configurable: true,
    value: MockGridFSBucket,
  });
  mongoose.connection.db = {
    collection(name) {
      assert.equal(name, "noteFiles.files");
      return {
        async updateOne(filter, update) {
          gridFsFileUpdate = { filter, update };
          return { matchedCount: 1 };
        },
      };
    },
  };
  User.findById = async () => user;
  Note.create = async (note) => {
    createdNote = note;
    return { id: "created-note-id" };
  };

  try {
    await uploadNote(
      {
        user: { id: ownerId.toString() },
        file: {
          originalname: "notes.pdf",
          mimetype: "application/pdf",
          buffer: Buffer.from("%PDF-test"),
          size: 9,
        },
        body: {},
      },
      {
        status() {
          return this;
        },
        json(body) {
          responseBody = body;
          return this;
        },
      }
    );
  } finally {
    Object.defineProperty(mongoose.mongo, "GridFSBucket", originalGridFSBucket);
    mongoose.connection.db = originalDb;
    User.findById = originalFindById;
    Note.create = originalCreate;
  }

  assert.equal(createdNote.user_id, userId);
  assert.equal(createdNote.uploadedBy.toString(), ownerId.toString());
  assert.equal(createdNote.fileId, fileId);
  assert.deepEqual(gridFsOptions.metadata, { contentType: "application/pdf" });
  assert.deepEqual(gridFsFileUpdate, {
    filter: { _id: fileId },
    update: { $set: { user_id: userId } },
  });
  assert.equal(responseBody.success, true);
});

test("profile photo uploads store the authenticated user ID on the top-level GridFS file", async () => {
  const originalGridFSBucket = Object.getOwnPropertyDescriptor(mongoose.mongo, "GridFSBucket");
  const originalDb = mongoose.connection.db;
  const originalFindById = User.findById;
  const userId = new mongoose.Types.ObjectId();
  const fileId = new mongoose.Types.ObjectId();
  let gridFsOptions;
  let gridFsFileUpdate;
  const user = {
    _id: userId,
    id: userId.toString(),
    user_id: "9876543210",
    async save() {},
  };
  class MockGridFSBucket {
    openUploadStream(_filename, options) {
      gridFsOptions = options;
      const stream = new EventEmitter();
      stream.id = fileId;
      stream.end = () => process.nextTick(() => stream.emit("finish"));
      return stream;
    }
  }
  Object.defineProperty(mongoose.mongo, "GridFSBucket", {
    configurable: true,
    value: MockGridFSBucket,
  });
  mongoose.connection.db = {
    collection(name) {
      assert.equal(name, "profilePhotos.files");
      return {
        async updateOne(filter, update) {
          gridFsFileUpdate = { filter, update };
          return { matchedCount: 1 };
        },
      };
    },
  };
  User.findById = async () => user;

  try {
    await updateProfilePhoto(
      {
        user: { id: userId.toString() },
        file: {
          mimetype: "image/png",
          buffer: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
        },
      },
      { json() { return this; } }
    );
  } finally {
    Object.defineProperty(mongoose.mongo, "GridFSBucket", originalGridFSBucket);
    mongoose.connection.db = originalDb;
    User.findById = originalFindById;
  }

  assert.deepEqual(gridFsOptions.metadata, { contentType: "image/png" });
  assert.deepEqual(gridFsFileUpdate, {
    filter: { _id: fileId },
    update: { $set: { user_id: user.user_id } },
  });
  assert.equal(user.profilePhotoFileId, fileId);
});

test("profile edits store the authenticated user ID on the top-level GridFS file", async () => {
  const originalGridFSBucket = Object.getOwnPropertyDescriptor(mongoose.mongo, "GridFSBucket");
  const originalDb = mongoose.connection.db;
  const originalFindById = User.findById;
  const originalFindOne = User.findOne;
  const ownerId = new mongoose.Types.ObjectId();
  const fileId = new mongoose.Types.ObjectId();
  const user = {
    _id: ownerId,
    id: ownerId.toString(),
    user_id: "9876543210",
    async save() {},
  };
  let gridFsFileUpdate;
  class MockGridFSBucket {
    openUploadStream() {
      const stream = new EventEmitter();
      stream.id = fileId;
      stream.end = () => process.nextTick(() => stream.emit("finish"));
      return stream;
    }
  }
  Object.defineProperty(mongoose.mongo, "GridFSBucket", {
    configurable: true,
    value: MockGridFSBucket,
  });
  mongoose.connection.db = {
    collection(name) {
      assert.equal(name, "profilePhotos.files");
      return {
        async updateOne(filter, update) {
          gridFsFileUpdate = { filter, update };
          return { matchedCount: 1 };
        },
      };
    },
  };
  User.findById = async () => user;
  User.findOne = async () => null;

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
    Object.defineProperty(mongoose.mongo, "GridFSBucket", originalGridFSBucket);
    mongoose.connection.db = originalDb;
    User.findById = originalFindById;
    User.findOne = originalFindOne;
  }

  assert.deepEqual(gridFsFileUpdate, {
    filter: { _id: fileId },
    update: { $set: { user_id: user.user_id } },
  });
  assert.equal(user.profilePhotoFileId, fileId);
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
