import assert from "node:assert/strict";
import bcrypt from "bcryptjs";
import express from "express";
import { randomBytes } from "node:crypto";
import test from "node:test";
import authRoutes from "../routes/auth.routes.js";
import notesRoutes from "../routes/notes.routes.js";
import { deleteMyNote, getNoteStats, listNotes } from "../controllers/notes.controller.js";
import { protect } from "../middlewares/authMiddleware.js";
import { hasValidFileSignature } from "../utils/fileValidation.js";
import {
  changePassword,
  loginUser,
  logoutUser,
  registerUser,
  verifyUser,
} from "../controllers/auth.controller.js";
import Note from "../models/Note.js";
import User from "../models/User.js";

test("password hashes are excluded from normal user queries", () => {
  assert.equal(User.schema.path("password").options.select, false);
});

test("password changes require authentication and the public reset route is absent", () => {
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

  const protectedNoteRoutes = notesRoutes.stack
    .map((layer) => layer.route)
    .filter(Boolean);
  const statsRoute = protectedNoteRoutes.find((route) => route.path === "/stats");
  assert.ok(statsRoute);
  assert.equal(statsRoute.stack.some((layer) => layer.handle === protect), false);
  for (const path of ["/upload", "/mine", "/:id", "/", "/:id/file"]) {
    const route = protectedNoteRoutes.find((candidate) => candidate.path === path);
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

test("registration stores a hash and only returns a generic success message", async () => {
  const originalFindOne = User.findOne;
  const originalCreate = User.create;
  const originalSecret = process.env.JWT_SECRET;
  const submittedPassword = "safe-test-password";
  let createdUser;
  let responseBody;
  let cookieOptions;
  const response = {
    cookie(_name, _value, options) {
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
    return { ...user, _id: "test-user-id" };
  };
  process.env.JWT_SECRET = randomBytes(32).toString("hex");

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
  assert.equal(await bcrypt.compare(submittedPassword, createdUser.password), true);
  assert.notEqual(createdUser.password, submittedPassword);
  assert.equal(cookieOptions.httpOnly, true);
  assert.equal("password" in responseBody, false);
  assert.equal("token" in responseBody, false);
  assert.equal(JSON.stringify(responseBody).includes(submittedPassword), false);
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
