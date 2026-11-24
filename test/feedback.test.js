import assert from "node:assert/strict";
import cookieParser from "cookie-parser";
import express from "express";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import test, { after } from "node:test";
import Feedback from "../models/Feedback.js";
import User from "../models/User.js";

process.env.NODE_ENV = "test";
process.env.JWT_SECRET = "feedback-test-jwt-secret-that-is-long-enough";
process.env.REDIS_URL = "";
process.env.RATE_LIMIT_FEEDBACK_WINDOW_MS = "60000";
process.env.RATE_LIMIT_FEEDBACK_MAX = "5";

const { default: feedbackRoutes } = await import("../routes/feedback.routes.js");
const { default: adminRoutes } = await import("../routes/admin.routes.js");

const app = express();
app.set("trust proxy", 1);
app.use(express.json());
app.use(cookieParser());
app.use("/api/feedback", feedbackRoutes);
app.use("/api/admin", adminRoutes);

const server = app.listen(0);
after(() => new Promise((resolve, reject) => {
  server.close((error) => (error ? reject(error) : resolve()));
}));

const sendFeedback = async ({ feedback, ip, token, identity } = {}) => {
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  return fetch(`http://127.0.0.1:${address.port}/api/feedback`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-forwarded-for": ip,
      ...(token ? { cookie: `token=${token}` } : {}),
    },
    body: JSON.stringify({ feedback, ...identity }),
  });
};

test("feedback model uses the explicit collection and limited fields", async () => {
  assert.equal(Feedback.collection.name, "feedback");
  assert.deepEqual(Object.keys(Feedback.schema.paths).sort(), [
    "_id",
    "createdAt",
    "feedback",
    "isAuthenticated",
    "user_info",
  ]);
  assert.equal(Feedback.schema.path("feedback").options.maxlength, 2000);
  const anonymousFeedback = new Feedback({ feedback: "A guest suggestion" });
  assert.equal(anonymousFeedback.user_info, null);
  assert.equal(anonymousFeedback.isAuthenticated, false);
  assert.equal("user" in anonymousFeedback.toObject(), false);
  assert.equal("userId" in anonymousFeedback.toObject(), false);
  await anonymousFeedback.validate();
});

test("feedback endpoint trusts only the verified account and accepts guests", async () => {
  const originalCreate = Feedback.create;
  const originalFindById = User.findById;
  const submissions = [];
  Feedback.create = async (document) => {
    submissions.push(document);
    return document;
  };
  const userId = new mongoose.Types.ObjectId();
  const authenticatedUser = {
    _id: userId,
    name: "Verified User",
    email: "verified@example.com",
    role: "USER",
    accountStatus: "active",
    deletedAt: null,
  };
  User.findById = () => ({ select: async () => authenticatedUser });
  const token = jwt.sign({ id: userId.toString() }, process.env.JWT_SECRET, { expiresIn: 3600 });

  try {
    const guestResponse = await sendFeedback({
      feedback: "  A useful suggestion  ",
      ip: "198.51.100.71",
      identity: {
        user_Id: "attacker-id",
        email: "attacker@example.com",
        isAuthenticated: true,
      },
    });
    const userResponse = await sendFeedback({
      feedback: "A private issue report",
      ip: "198.51.100.72",
      token,
      identity: {
        user_Id: "attacker-id",
        email: "attacker@example.com",
        isAuthenticated: false,
      },
    });
    const maximumLengthResponse = await sendFeedback({
      feedback: "x".repeat(2000),
      ip: "198.51.100.73",
    });

    assert.equal(guestResponse.status, 201);
    assert.equal(userResponse.status, 201);
    assert.equal(maximumLengthResponse.status, 201);
    assert.deepEqual(await guestResponse.json(), {
      success: true,
      message: "Feedback submitted successfully",
    });
    assert.equal(submissions.length, 3);
    assert.equal(submissions[0].feedback, "A useful suggestion");
    assert.equal("user" in submissions[0], false);
    assert.equal("userId" in submissions[0], false);
    assert.equal(submissions[0].isAuthenticated, false);
    assert.equal("user" in submissions[1], false);
    assert.equal("userId" in submissions[1], false);
    assert.deepEqual(submissions[1].user_info, {
      user_Id: userId.toString(),
      name: "Verified User",
      email: "verified@example.com",
    });
    assert.equal(submissions[1].isAuthenticated, true);
    assert.equal(submissions[2].feedback.length, 2000);
  } finally {
    Feedback.create = originalCreate;
    User.findById = originalFindById;
  }
});

test("admin feedback endpoint is protected and returns submitter details", async () => {
  const originalFindById = User.findById;
  const originalUserFind = User.find;
  const originalFind = Feedback.find;
  const originalCountDocuments = Feedback.countDocuments;
  const userId = new mongoose.Types.ObjectId();
  const adminId = new mongoose.Types.ObjectId();
  const legacyUserId = new mongoose.Types.ObjectId();
  const token = jwt.sign({ id: adminId.toString() }, process.env.JWT_SECRET, { expiresIn: 3600 });
  const submittedAt = new Date("2026-11-24T10:30:00.000Z");
  User.findById = () => ({
    select: async () => ({
      _id: adminId,
      name: "Admin",
      email: "admin@example.com",
      role: "ADMIN",
      accountStatus: "active",
      deletedAt: null,
    }),
  });
  User.find = () => ({
    select() {
      return {
        lean: async () => [{
          _id: legacyUserId,
          name: "Legacy User",
          email: "legacy@example.com",
        }],
      };
    },
  });
  Feedback.find = () => ({
    sort() { return this; },
    skip() { return this; },
    limit() { return this; },
    populate() { return this; },
    lean: async () => [{
      _id: new mongoose.Types.ObjectId(),
      feedback: "A useful suggestion",
      user: userId,
      user_info: { user_Id: userId.toString(), name: "Verified User", email: "verified@example.com" },
      isAuthenticated: true,
      createdAt: submittedAt,
    }, {
      _id: new mongoose.Types.ObjectId(),
      feedback: "An older suggestion",
      userId: legacyUserId,
      createdAt: submittedAt,
    }],
  });
  Feedback.countDocuments = async () => 2;

  try {
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const unauthorized = await fetch(`http://127.0.0.1:${address.port}/api/admin/feedback`);
    const response = await fetch(`http://127.0.0.1:${address.port}/api/admin/feedback`, {
      headers: { cookie: `token=${token}` },
    });
    assert.equal(unauthorized.status, 401);
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.records[0].user_info.name, "Verified User");
    assert.equal(result.records[0].user_info.email, "verified@example.com");
    assert.equal(result.records[0].isAuthenticated, true);
    assert.equal(result.records[0].createdAt, submittedAt.toISOString());
    assert.equal(result.records[1].user_info.name, "Legacy User");
    assert.equal(result.records[1].user_info.email, "legacy@example.com");
    assert.equal(result.records[1].isAuthenticated, true);
  } finally {
    User.findById = originalFindById;
    User.find = originalUserFind;
    Feedback.find = originalFind;
    Feedback.countDocuments = originalCountDocuments;
  }
});

test("feedback endpoint rejects empty, whitespace-only, and oversized text", async () => {
  const originalCreate = Feedback.create;
  Feedback.create = async () => assert.fail("Invalid feedback must not be stored");

  try {
    for (const [index, feedback] of ["", " \t\n ", "x".repeat(2001)].entries()) {
      const response = await sendFeedback({
        feedback,
        ip: `198.51.100.${80 + index}`,
      });
      assert.equal(response.status, 400);
    }
  } finally {
    Feedback.create = originalCreate;
  }
});

test("feedback is stored with a line break after every 15 words", async () => {
  const originalCreate = Feedback.create;
  let submittedDocument;
  Feedback.create = async (document) => {
    submittedDocument = document;
    return document;
  };
  const words = Array.from({ length: 32 }, (_, index) => `word${index + 1}`);

  try {
    const response = await sendFeedback({
      feedback: words.join(" "),
      ip: "198.51.100.91",
    });
    assert.equal(response.status, 201);
    assert.equal(
      submittedDocument.feedback,
      [
        words.slice(0, 15).join(" "),
        words.slice(15, 30).join(" "),
        words.slice(30).join(" "),
      ].join("\n")
    );
  } finally {
    Feedback.create = originalCreate;
  }
});

test("feedback endpoint returns a safe error when MongoDB storage fails", async () => {
  const originalCreate = Feedback.create;
  Feedback.create = async () => {
    throw new Error("database details must not reach the response");
  };

  try {
    const response = await sendFeedback({
      feedback: "A valid report",
      ip: "198.51.100.90",
    });
    assert.equal(response.status, 500);
    assert.deepEqual(await response.json(), { message: "Could not submit feedback" });
  } finally {
    Feedback.create = originalCreate;
  }
});
