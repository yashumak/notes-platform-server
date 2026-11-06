import assert from "node:assert/strict";
import express from "express";
import multer from "multer";
import test, { after } from "node:test";
import { apiRequestLogger } from "../middlewares/apiRequestLogger.js";
import { createDataMasker, maskSensitiveData } from "../utils/dataMasking.js";

const app = express();
const upload = multer({ storage: multer.memoryStorage() });
app.use("/api", apiRequestLogger);
app.use(express.json());
app.post("/api/auth/login/:accountId", (req, res) =>
  res.json({
    email: req.body.email,
    password: req.body.password,
    accessToken: "response-access-token",
    user: {
      name: "Yash Example",
      email: req.body.email,
      expiresAt: 1793904684000,
      isAuthenticated: true,
    },
    uploadUrl:
      "https://private-bucket.s3.amazonaws.com/object?X-Amz-Signature=temporary-signature",
  })
);
app.post("/api/upload", upload.single("file"), (req, res) =>
  res.json({
    success: true,
    uploadToken: req.body.uploadToken,
    fileName: req.file.originalname,
  })
);

const server = app.listen(0);
after(() => new Promise((resolve, reject) => {
  server.close((error) => (error ? reject(error) : resolve()));
}));

const captureRequest = async (path, init) => {
  const logs = [];
  const originalLog = console.log;
  console.log = (...args) => logs.push(args.join(" "));
  try {
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const response = await fetch(`http://127.0.0.1:${address.port}${path}`, init);
    return { response, logs };
  } finally {
    console.log = originalLog;
  }
};

test("masks sensitive fields recursively without changing API data", () => {
  const source = {
    email: "yash@example.com",
    password: "MyPassword123",
    accessToken: "token-value",
    expiresAt: 1793904684000,
    isAuthenticated: true,
    user: [
      {
        name: "Yash Example",
        profilePhotoUrl: "/api/auth/profile/photo?v=private-object-key",
        notes: "private lecture notes",
      },
    ],
    nested: { authorization: "Bearer secret", values: [{ phoneNumber: "+1-555-555-0100" }] },
    safeUrl: "https://example.com/public?token=leaked-token",
    notice: "Open https://bucket.s3.amazonaws.com/file?X-Amz-Signature=private-signature now",
    storageReference: "https://private-bucket.s3.amazonaws.com/notes/private-object",
    pathStyleStorageReference: "https://s3.amazonaws.com/private-bucket/private-object",
    databaseReference: "mongodb+srv://account:password@database.example.net/noteshub",
    diagnostic: "AWS_SECRET_ACCESS_KEY=example-secret",
    encryptedData: "encrypted-auth-payload",
    embedded: "Contact yash@example.com with Bearer secret-token",
    nullable: null,
  };
  const copy = structuredClone(source);
  const result = maskSensitiveData(source);

  assert.deepEqual(result, {
    email: "y***@example.com",
    password: "********",
    accessToken: "********",
    expiresAt: 1793904684000,
    isAuthenticated: true,
    user: [
      {
        name: "Y***",
        profilePhotoUrl: "[REDACTED]",
        notes: "[REDACTED]",
      },
    ],
    nested: { authorization: "********", values: [{ phoneNumber: "[REDACTED]" }] },
    safeUrl: "https://example.com/public?token=[REDACTED]",
    notice: "Open [REDACTED] now",
    storageReference: "[REDACTED]",
    pathStyleStorageReference: "[REDACTED]",
    databaseReference: "[REDACTED]",
    diagnostic: "AWS_SECRET_ACCESS_KEY=[REDACTED]",
    encryptedData: "[REDACTED]",
    embedded: "Contact y***@example.com with Bearer [REDACTED]",
    nullable: null,
  });
  assert.deepEqual(source, copy);
  assert.equal(maskSensitiveData(undefined), undefined);
  assert.equal(maskSensitiveData(null), null);
  const parsedWithPrototypeKey = maskSensitiveData(
    JSON.parse('{"__proto__":{"password":"not-a-password"}}')
  );
  assert.equal(Object.hasOwn(parsedWithPrototypeKey, "__proto__"), true);
  assert.equal(parsedWithPrototypeKey.__proto__.password, "********");
});

test("supports additional masking rules and safely handles cycles and binary data", () => {
  const masker = createDataMasker({
    sensitiveKeys: ["internalMemo"],
    redactKeys: ["privateValue"],
    maskedValue: "***",
    redactedValue: "[HIDDEN]",
  });
  const cyclic = { internalMemo: "secret", privateValue: "private", bytes: Buffer.from("file") };
  cyclic.self = cyclic;

  assert.deepEqual(masker(cyclic), {
    internalMemo: "***",
    privateValue: "[HIDDEN]",
    bytes: "[HIDDEN]",
    self: "[Circular]",
  });
  assert.equal(maskSensitiveData({ optionalToken: "secret" }, { sensitiveKeys: ["optionalToken"] })
    .optionalToken, "********");
});

test("logs sanitized request and response data without changing the response", async () => {
  const { response, logs } = await captureRequest(
    "/api/auth/login/actual-account-id?email=query@example.com&accessToken=query-token&v=photos%2Fprivate-object-key",
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer header-secret",
        cookie: "session=private-cookie",
      },
      body: JSON.stringify({
        email: "user@example.com",
        password: "request-password",
        nested: [{ name: "Private Name", notes: "private note contents" }],
      }),
    }
  );
  const responseBody = await response.json();

  assert.equal(response.status, 200);
  assert.equal(responseBody.email, "user@example.com");
  assert.equal(responseBody.password, "request-password");
  assert.equal(responseBody.uploadUrl.includes("temporary-signature"), true);
  assert.equal(logs.length, 1);
  assert.equal(logs[0].includes("request-password"), false);
  assert.equal(logs[0].includes("header-secret"), false);
  assert.equal(logs[0].includes("private-cookie"), false);
  assert.equal(logs[0].includes("private note contents"), false);
  assert.equal(logs[0].includes("temporary-signature"), false);

  const logged = JSON.parse(logs[0]);
  assert.equal(logged.event, "http.request");
  assert.equal(logged.context.route, "/api/auth/login/:accountId");
  assert.deepEqual(logged.context.requestBody, {
    email: "u***@example.com",
    password: "********",
    nested: [{ name: "P***", notes: "[REDACTED]" }],
  });
  assert.equal(logged.context.queryParameters.email, "q***@example.com");
  assert.equal(logged.context.queryParameters.accessToken, "********");
  assert.equal(logged.context.queryParameters.v, "[REDACTED]");
  assert.equal(logged.context.response.password, "********");
  assert.equal(logged.context.response.user.email, "u***@example.com");
  assert.equal(logged.context.response.uploadUrl, "[REDACTED]");
  assert.equal(logged.context.response.user.expiresAt, 1793904684000);
});

test("multipart uploads log metadata only and never file contents", async () => {
  const form = new FormData();
  form.append("uploadToken", "multipart-upload-token");
  form.append("description", "private upload description");
  form.append("file", new Blob(["UNIQUE_PRIVATE_FILE_CONTENT"]), "private-filename.pdf");

  const { response, logs } = await captureRequest("/api/upload", {
    method: "POST",
    body: form,
  });
  const responseBody = await response.json();

  assert.equal(response.status, 200);
  assert.equal(responseBody.uploadToken, "multipart-upload-token");
  assert.equal(logs.length, 1);
  for (const secret of [
    "multipart-upload-token",
    "private upload description",
    "UNIQUE_PRIVATE_FILE_CONTENT",
    "private-filename.pdf",
  ]) {
    assert.equal(logs[0].includes(secret), false);
  }
  const logged = JSON.parse(logs[0]);
  assert.equal(logged.context.uploadedFiles, 1);
  assert.deepEqual(logged.context.requestBody, {
    uploadToken: "********",
    description: "[REDACTED]",
  });
  assert.equal(logged.context.response.uploadToken, "********");
});
