import { ListObjectsV2Command, GetObjectCommand, S3Client } from "@aws-sdk/client-s3";
import mongoose from "mongoose";
import Note from "../models/Note.js";
import User from "../models/User.js";
import { loadAppSecrets, getAppSecrets } from "../config/secrets.js";

await loadAppSecrets();

const METADATA_PREFIX = "metadata/";
const BATCH_SIZE = 25;
const MAX_ATTEMPTS = 3;
const RETRYABLE_NAMES = new Set([
  "ECONNRESET",
  "ETIMEDOUT",
  "RequestTimeout",
  "RequestTimeoutException",
  "SlowDown",
  "ServiceUnavailable",
  "InternalError",
  "MongoNetworkError",
  "MongoNetworkTimeoutError",
  "MongoServerSelectionError",
]);

const migrationError = (code, message) => Object.assign(new Error(message), { code });
const getErrorCode = (error) =>
  String(error?.Code || error?.code || error?.name || "UNKNOWN_ERROR").slice(0, 80);
const isRetryable = (error) =>
  Boolean(error?.$retryable) ||
  error?.$metadata?.httpStatusCode === 408 ||
  error?.$metadata?.httpStatusCode === 429 ||
  error?.$metadata?.httpStatusCode >= 500 ||
  RETRYABLE_NAMES.has(error?.name) ||
  RETRYABLE_NAMES.has(error?.code);

const createReport = (mode) => ({
  mode,
  startedAt: new Date().toISOString(),
  completedAt: null,
  totalS3Objects: 0,
  totalMongoRecordsIdentified: 0,
  existingMongoRecords: 0,
  newRecordsInserted: 0,
  existingRecordsUpdated: 0,
  recordsSkipped: 0,
  duplicateRecords: 0,
  failedOperations: 0,
  missingS3Objects: 0,
  unmatchedObjects: [],
  unresolvedOwnerIds: [],
  plan: {
    notesToInsert: 0,
    notesToSkip: 0,
    notesToUpdate: 0,
  },
});

const persistReport = async (reportPath, report) => {
  const { writeFile, mkdir } = await import("node:fs/promises");
  const path = await import("node:path");
  const reportDir = path.dirname(reportPath);
  await mkdir(reportDir, { recursive: true });
  await writeFile(reportPath, JSON.stringify(report, null, 2));
};

const withRetry = async (fn, attempt = 1) => {
  try {
    return await fn();
  } catch (error) {
    if (attempt < MAX_ATTEMPTS && isRetryable(error)) {
      await new Promise((resolve) => setTimeout(resolve, 500 * attempt));
      return withRetry(fn, attempt + 1);
    }
    throw error;
  }
};

const run = async ({ mode }) => {
  const secrets = getAppSecrets();
  if (!secrets.mongoUri) throw migrationError("MONGO_URI_MISSING", "MONGO_URI is required");
  const bucket = secrets.s3Bucket;
  if (!bucket) throw migrationError("S3_BUCKET_MISSING", "AWS_S3_BUCKET is required");
  const region = secrets.awsRegion;

  await mongoose.connect(secrets.mongoUri);
  const client = new S3Client({ region });

  const report = createReport(mode);
  try {
    const s3Keys = [];
    let continuationToken;
    do {
      const page = await withRetry(() =>
        client.send(
          new ListObjectsV2Command({
            Bucket: bucket,
            Prefix: METADATA_PREFIX,
            ContinuationToken: continuationToken,
          })
        )
      );
      for (const object of page.Contents || []) {
        if (object.Key?.endsWith(".json")) {
          s3Keys.push(object.Key);
        }
      }
      continuationToken = page.IsTruncated ? page.NextContinuationToken : undefined;
    } while (continuationToken);

    report.totalS3Objects = s3Keys.length;
    console.log(`Found ${s3Keys.length} metadata object(s) in S3 under ${METADATA_PREFIX}`);

    const notesToMigrate = [];
    const existingIds = new Set();

    const existingRecords = await Note.find({}, { s3MetadataId: 1, _id: 0 }).lean();
    for (const record of existingRecords) {
      if (record.s3MetadataId) existingIds.add(String(record.s3MetadataId));
    }
    report.existingMongoRecords = existingIds.size;

    for (const key of s3Keys) {
      try {
        const result = await withRetry(() =>
          client.send(new GetObjectCommand({ Bucket: bucket, Key: key }))
        );
        if (!result.Body) {
          report.missingS3Objects += 1;
          report.unmatchedObjects.push({ key, reason: "empty body" });
          continue;
        }
        const body = await result.Body.transformToString();
        let note;
        try {
          note = JSON.parse(body);
        } catch {
          report.failedOperations += 1;
          report.unmatchedObjects.push({ key, reason: "invalid JSON" });
          continue;
        }

        const noteId = note._id || note.s3MetadataId || key.slice(METADATA_PREFIX.length).replace(/\.json$/, "");

        if (existingIds.has(String(noteId))) {
          report.duplicateRecords += 1;
          report.recordsSkipped += 1;
          report.plan.notesToSkip += 1;
          continue;
        }

        if (!note.title || !note.fileName || !note.contentType || note.fileSize === undefined) {
          report.failedOperations += 1;
          report.unmatchedObjects.push({ key, reason: "missing required fields" });
          continue;
        }

        let uploadedBy = null;
        if (note.uploadedBy && mongoose.isValidObjectId(note.uploadedBy)) {
          const userExists = await User.exists({ _id: note.uploadedBy });
          if (userExists) {
            uploadedBy = note.uploadedBy;
          } else {
            report.unresolvedOwnerIds.push(note.uploadedBy);
          }
        }

        notesToMigrate.push({ key, noteId, note, uploadedBy });
        report.plan.notesToInsert += 1;
      } catch (error) {
        report.failedOperations += 1;
        report.unmatchedObjects.push({ key, reason: getErrorCode(error) });
        console.error(`Failed to process ${key}: ${getErrorCode(error)}`);
      }
    }

    report.totalMongoRecordsIdentified = notesToMigrate.length + report.duplicateRecords;

    if (mode === "apply") {
      for (let i = 0; i < notesToMigrate.length; i += BATCH_SIZE) {
        const batch = notesToMigrate.slice(i, i + BATCH_SIZE);
        const docs = batch.map(({ noteId, note, uploadedBy }) => ({
          _id: noteId,
          s3MetadataId: String(noteId),
          title: note.title,
          description: note.description || "",
          fileName: note.fileName,
          contentType: note.contentType,
          fileSize: Number(note.fileSize),
          university: note.university || "",
          course: note.course || "",
          subject: note.subject || "",
          category: note.category || note.studyType || "",
          studyType: note.studyType || note.category || "",
          year: note.year ? Number(note.year) : undefined,
          tags: Array.isArray(note.tags) ? note.tags : [],
          visibility: note.visibility === "private" ? "private" : "public",
          uploadStatus: note.uploadStatus || "active",
          storageProvider: "s3",
          s3Key: note.s3Key || "",
          s3ObjectMetadata: note.s3ObjectMetadata || {},
          uploadedBy: uploadedBy || mongoose.Types.ObjectId(),
          user_id: note.user_id || undefined,
          createdAt: note.createdAt ? new Date(note.createdAt) : new Date(),
        }));

        try {
          await Note.insertMany(docs, { ordered: false });
          report.newRecordsInserted += docs.length;
        } catch (error) {
          const inserted = error?.writeErrors ? docs.length - error.writeErrors.length : 0;
          report.newRecordsInserted += inserted > 0 ? inserted : 0;
          report.failedOperations += error?.writeErrors ? error.writeErrors.length : 1;
          for (const we of error?.writeErrors || []) {
            report.unmatchedObjects.push({
              key: batch[we.index]?.key || "unknown",
              reason: `duplicate key: ${we.errmsg}`,
            });
          }
        }
      }
    }

    report.completedAt = new Date().toISOString();

    console.log("\n=== Migration Summary ===");
    console.log(`Mode: ${mode}`);
    console.log(`Total S3 metadata objects found: ${report.totalS3Objects}`);
    console.log(`Existing MongoDB records: ${report.existingMongoRecords}`);
    console.log(`New records inserted: ${report.newRecordsInserted}`);
    console.log(`Duplicate records skipped: ${report.duplicateRecords}`);
    console.log(`Failed operations: ${report.failedOperations}`);
    console.log(`Unresolved owner IDs: ${report.unresolvedOwnerIds.length}`);
    if (report.unresolvedOwnerIds.length > 0) {
      console.log(`  Unresolved owner IDs: ${report.unresolvedOwnerIds.join(", ")}`);
    }
    if (report.unmatchedObjects.length > 0) {
      console.log(`Unmatched/failed objects:`);
      for (const item of report.unmatchedObjects) {
        console.log(`  - ${item.key}: ${item.reason}`);
      }
    }
    console.log("========================\n");

    const path = await import("node:path");
    const reportPath = path.join(
      "c:\\Users\\USER\\OneDrive\\Desktop\\notes-platform\\backend\\migration-reports",
      `s3-to-mongodb-migration-${Date.now()}.json`
    );
    await persistReport(reportPath, report);
    console.log(`Report saved to ${reportPath}`);

    if (report.failedOperations > 0) {
      process.exitCode = 1;
    }
  } finally {
    client.destroy();
    await mongoose.disconnect();
  }
};

const parseArguments = (args) => {
  const options = { mode: "dry-run" };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (["--dry-run", "--apply", "--verify"].includes(arg)) {
      options.mode = arg.slice(2);
    }
  }
  return options;
};

const scriptPath = require("node:path").resolve(process.argv[1] || "");
const currentUrl = require("node:url").fileURLToPath(import.meta.url);
if (scriptPath === currentUrl) {
  try {
    await run(parseArguments(process.argv.slice(2)));
  } catch (error) {
    console.error(JSON.stringify({
      status: "failed",
      code: getErrorCode(error),
      message: error.message,
    }, null, 2));
    process.exitCode = 1;
  }
}