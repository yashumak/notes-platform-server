import dotenv from "dotenv";
dotenv.config();

import { appendFile, mkdir, readdir, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import {
  GetObjectCommand,
  HeadObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import { Upload } from "@aws-sdk/lib-storage";
import mongoose from "mongoose";
import Note from "../models/Note.js";
import User from "../models/User.js";
import { sanitizeFileName } from "../utils/fileValidation.js";

const SCRIPT_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPORT_DIRECTORY = path.resolve(SCRIPT_DIRECTORY, "..", "migration-reports");
const LOCAL_STORAGE_DIRECTORY = path.resolve(SCRIPT_DIRECTORY, "..", "uploads");
const BACKUP_COLLECTION_PREFIX = "noteshub_s3_migration_backup_";
const MAX_UPLOAD_ATTEMPTS = 3;
const RETRYABLE_STATUS_CODES = new Set([408, 429]);

const migrationError = (code, message) => Object.assign(new Error(message), { code });

const parseArguments = (args) => {
  const options = { mode: undefined, backupId: undefined };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--dry-run" || argument === "--backup" || argument === "--apply") {
      if (options.mode) {
        throw migrationError("INVALID_ARGUMENTS", "Choose exactly one migration mode");
      }
      options.mode = argument.slice(2);
    } else if (argument === "--backup-id") {
      options.backupId = args[index + 1];
      index += 1;
    } else {
      throw migrationError("INVALID_ARGUMENTS", "Unknown migration option");
    }
  }
  options.mode ||= "dry-run";
  if (options.mode === "apply" && !/^[a-zA-Z0-9_-]{1,80}$/.test(options.backupId || "")) {
    throw migrationError("BACKUP_REQUIRED", "--apply requires a completed backup ID");
  }
  if (options.mode !== "apply" && options.backupId) {
    throw migrationError("INVALID_ARGUMENTS", "--backup-id is only valid with --apply");
  }
  return options;
};

const hasFileReference = (record, fileIdField, s3KeyField) =>
  Boolean(record[fileIdField] || record[s3KeyField]);

const getContentType = (file, records, typeField) =>
  records.find((record) => record[typeField])?.[typeField] ||
  file.metadata?.contentType ||
  file.contentType ||
  "application/octet-stream";

const getObjectKey = (bucketName, file) =>
  `${bucketName === "noteFiles" ? "notes" : "photos"}/${file._id}/${sanitizeFileName(file.filename)}`;

const isNotFound = (error) =>
  error?.name === "NotFound" ||
  error?.name === "NoSuchKey" ||
  error?.$metadata?.httpStatusCode === 404;

const isPreconditionFailure = (error) =>
  error?.name === "PreconditionFailed" ||
  error?.name === "ConditionalRequestConflict" ||
  [409, 412].includes(error?.$metadata?.httpStatusCode);

const getErrorCode = (error) =>
  String(error?.Code || error?.code || error?.name || "UNKNOWN_ERROR").slice(0, 80);

const RETRYABLE_ERROR_NAMES = new Set([
    "ECONNRESET",
    "ECONNREFUSED",
    "ETIMEDOUT",
    "EPIPE",
    "RequestTimeout",
    "RequestTimeoutException",
    "SlowDown",
    "ServiceUnavailable",
    "InternalError",
    "TimeoutError",
]);

const isRetryable = (error) =>
  Boolean(error?.$retryable) ||
  RETRYABLE_STATUS_CODES.has(error?.$metadata?.httpStatusCode) ||
  error?.$metadata?.httpStatusCode >= 500 ||
  [error?.code, error?.name, error?.Code].some((code) => RETRYABLE_ERROR_NAMES.has(code));

const createReport = (mode) => ({
  mode,
  startedAt: new Date().toISOString(),
  completedAt: null,
  mongoNoteRecordsScanned: 0,
  mongoUserRecordsScanned: 0,
  totalMongoRecordsIdentified: 0,
  recordsWouldBeUpdated: 0,
  totalPdfFilesFound: 0,
  totalProfilePhotosFound: 0,
  totalGridFsFilesFound: 0,
  localStorageFilesFound: 0,
  filesSuccessfullyUploaded: 0,
  filesVerified: 0,
  recordsSuccessfullyUpdated: 0,
  skippedOrDuplicateFiles: 0,
  missingOrInaccessibleFiles: [],
  failedUploads: [],
  unresolvedLocalPaths: [],
});

const recordLog = async (logPath, entry) => {
  await appendFile(logPath, `${JSON.stringify({ at: new Date().toISOString(), ...entry })}\n`, "utf8");
};

const saveReport = async (reportPath, report) => {
  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
};

const scanRecords = async (collection, fields, report, recordKind) => {
  const projection = {
    _id: 1,
    [fields.fileId]: 1,
    [fields.s3Key]: 1,
    [fields.contentType]: 1,
  };
  const cursor = collection.find(
    {},
    { projection }
  );
  const records = [];
  for await (const record of cursor) {
    if (recordKind === "note") report.mongoNoteRecordsScanned += 1;
    else report.mongoUserRecordsScanned += 1;
    if (hasFileReference(record, fields.fileId, fields.s3Key)) {
      report.totalMongoRecordsIdentified += 1;
      records.push(record);
    }
  }
  return records;
};

const scanLocalPathReferences = async (collection, fields, kind) => {
  const cursor = collection.find(
    {},
    { projection: { _id: 1, ...Object.fromEntries(fields.map((field) => [field, 1])) } }
  );
  const references = [];
  for await (const record of cursor) {
    for (const field of fields) {
      if (typeof record[field] === "string" && record[field].trim()) {
        references.push({ kind, recordId: String(record._id), field });
      }
    }
  }
  return references;
};

const scanGridFsFiles = async (collection) => {
  const files = [];
  for await (const file of collection.find({})) files.push(file);
  return files;
};

const scanLocalStorageFiles = async (directory, relativeDirectory = "") => {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
  const files = [];
  for (const entry of entries) {
    const relativePath = path.join(relativeDirectory, entry.name).replace(/\\/g, "/");
    if (entry.isDirectory()) {
      files.push(
        ...(await scanLocalStorageFiles(
          path.join(directory, entry.name),
          relativePath
        ))
      );
    } else {
      files.push({ kind: "local-file", recordId: relativePath, field: "uploads/" });
    }
  }
  return files;
};

const calculateGridFsChecksum = async (fileId, sourceBucket) => {
  const hash = createHash("sha256");
  const bucket = new mongoose.mongo.GridFSBucket(mongoose.connection.db, {
    bucketName: sourceBucket,
  });
  const stream = bucket.openDownloadStream(fileId);
  try {
    for await (const chunk of stream) hash.update(chunk);
    return hash.digest("base64");
  } catch {
    stream.destroy();
    const error = new Error("Could not read the GridFS source file");
    error.code = "GRIDFS_SOURCE_READ_FAILED";
    throw error;
  }
};

const createBackup = async (db, noteCollection, userCollection, backupId) => {
  const name = `${BACKUP_COLLECTION_PREFIX}${backupId}`;
  const backupCollection = db.collection(name);
  await backupCollection.insertOne({
    _id: "manifest",
    status: "in_progress",
    createdAt: new Date(),
    database: db.databaseName,
    collections: { notes: 0, users: 0 },
  });

  const backupRecords = async (collection, kind, fields, matchFields = fields) => {
    const projection = { _id: 1, ...Object.fromEntries(fields.map((field) => [field, 1])) };
    const cursor = collection.find(
      { $or: matchFields.map((field) => ({ [field]: { $exists: true, $ne: null } })) },
      { projection }
    );
    let batch = [];
    let count = 0;
    for await (const record of cursor) {
      batch.push({
        _id: `${kind}:${record._id}`,
        kind,
        documentId: record._id,
        original: record,
      });
      if (batch.length === 500) {
        await backupCollection.insertMany(batch, { ordered: true });
        count += batch.length;
        batch = [];
      }
    }
    if (batch.length) {
      await backupCollection.insertMany(batch, { ordered: true });
      count += batch.length;
    }
    return count;
  };

  try {
    const [notes, users] = await Promise.all([
      backupRecords(
        noteCollection,
        "note",
        ["fileId", "s3Key", "storageProvider"],
        ["fileId", "s3Key"]
      ),
      backupRecords(userCollection, "user", [
        "profilePhotoFileId",
        "profilePhotoS3Key",
        "profilePhotoContentType",
      ]),
    ]);
    await backupCollection.updateOne(
      { _id: "manifest" },
      { $set: { status: "complete", completedAt: new Date(), collections: { notes, users } } }
    );
    return { name, notes, users };
  } catch (error) {
    await backupCollection.updateOne(
      { _id: "manifest" },
      { $set: { status: "failed", failedAt: new Date(), errorCode: getErrorCode(error) } }
    ).catch(() => {});
    throw error;
  }
};

const readBackup = async (db, backupId) => {
  const collection = db.collection(`${BACKUP_COLLECTION_PREFIX}${backupId}`);
  const manifest = await collection.findOne({ _id: "manifest", status: "complete" });
  if (!manifest) {
    throw migrationError("BACKUP_NOT_FOUND", "The requested completed backup was not found");
  }
  const backups = new Map();
  for await (const entry of collection.find({ _id: { $ne: "manifest" } })) {
    backups.set(entry._id, entry.original);
  }
  return backups;
};

const ensureOriginalRecordIsBackedUp = (backups, kind, current, expectedFileId) => {
  const recordKind = kind === "photo" ? "user" : kind;
  const original = backups.get(`${recordKind}:${current._id}`);
  if (!original) {
    throw migrationError("BACKUP_RECORD_MISSING", `Backup does not contain ${recordKind} record`);
  }
  const fileId = recordKind === "note" ? current.fileId : current.profilePhotoFileId;
  const s3Key = recordKind === "note" ? current.s3Key : current.profilePhotoS3Key;
  if (String(fileId) !== String(expectedFileId)) {
    throw migrationError("BACKUP_STATE_CHANGED", `${recordKind} record changed after the backup`);
  }
  const originalFileId = recordKind === "note" ? original.fileId : original.profilePhotoFileId;
  const originalS3Key = recordKind === "note" ? original.s3Key : original.profilePhotoS3Key;
  if (String(originalFileId) !== String(expectedFileId) || originalS3Key) {
    throw migrationError("BACKUP_STATE_MISMATCH", `${recordKind} record does not match the backup`);
  }
  if (s3Key) {
    throw migrationError("RECORD_CHANGED", `${recordKind} record changed during migration`);
  }
  return true;
};

const headObject = async (s3, bucket, key) => {
  try {
    return await s3.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
  } catch (error) {
    if (isNotFound(error)) return null;
    throw error;
  }
};

const verifyObject = (
  head,
  file,
  contentType,
  sourceBucket,
  requireMigrationMetadata
) => {
  const metadataMatches =
    !requireMigrationMetadata ||
    (head.Metadata?.["migration-source-id"] === String(file._id) &&
      head.Metadata?.["migration-source-bucket"] === sourceBucket);
  return Boolean(
    head &&
    head.ContentLength === file.length &&
    head.ContentType === contentType &&
    head.ServerSideEncryption === "AES256" &&
    metadataMatches
  );
};

const getS3ObjectChecksum = async (s3, bucket, key) => {
  const result = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
  if (!result.Body) {
    throw migrationError("S3_VERIFICATION_FAILED", "Uploaded S3 object has no readable body");
  }
  const hash = createHash("sha256");
  for await (const chunk of result.Body) hash.update(chunk);
  return hash.digest("base64");
};

const verifyMigratedObject = async ({
  s3,
  bucket,
  key,
  file,
  contentType,
  sourceBucket,
  checksum,
}) => {
  const head = await headObject(s3, bucket, key);
  if (!head || !verifyObject(head, file, contentType, sourceBucket, true)) return false;
  return (await getS3ObjectChecksum(s3, bucket, key)) === checksum;
};

const uploadGridFsFile = async ({
  s3,
  bucket,
  sourceBucket,
  file,
  contentType,
  checksum,
  key,
  report,
}) => {
  const existing = await headObject(s3, bucket, key);
  if (existing) {
    if (
      !verifyObject(existing, file, contentType, sourceBucket, true) ||
      (await getS3ObjectChecksum(s3, bucket, key)) !== checksum
    ) {
      throw migrationError("S3_OBJECT_CONFLICT", "An existing S3 object conflicts with the migration file");
    }
    report.skippedOrDuplicateFiles += 1;
    report.filesVerified += 1;
    return "skipped";
  }

  const gridFsBucket = new mongoose.mongo.GridFSBucket(mongoose.connection.db, {
    bucketName: sourceBucket,
  });
  for (let attempt = 1; attempt <= MAX_UPLOAD_ATTEMPTS; attempt += 1) {
    const stream = gridFsBucket.openDownloadStream(file._id);
    try {
      const upload = new Upload({
        client: s3,
        params: {
          Bucket: bucket,
          Key: key,
          Body: stream,
          ContentLength: file.length,
          ContentType: contentType,
          ChecksumAlgorithm: "SHA256",
          ServerSideEncryption: "AES256",
          IfNoneMatch: "*",
          Metadata: {
            "migration-source-id": String(file._id),
            "migration-source-bucket": sourceBucket,
          },
        },
        partSize: 8 * 1024 * 1024,
        queueSize: 2,
        leavePartsOnError: false,
      });
      await upload.done();
      const verified = await verifyMigratedObject({
        s3,
        bucket,
        key,
        file,
        contentType,
        sourceBucket,
        checksum,
      });
      if (!verified) {
        throw migrationError("S3_VERIFICATION_FAILED", "Uploaded S3 object failed verification");
      }
      report.filesSuccessfullyUploaded += 1;
      report.filesVerified += 1;
      return "uploaded";
    } catch (error) {
      stream.destroy();
      if (isPreconditionFailure(error)) {
        if (await verifyMigratedObject({
          s3,
          bucket,
          key,
          file,
          contentType,
          sourceBucket,
          checksum,
        })) {
          report.skippedOrDuplicateFiles += 1;
          report.filesVerified += 1;
          return "skipped";
        }
        throw migrationError("S3_OBJECT_CONFLICT", "A conflicting S3 object prevented the upload");
      }
      if (attempt === MAX_UPLOAD_ATTEMPTS || !isRetryable(error)) throw error;
      await delay(250 * 2 ** (attempt - 1));
    }
  }
  throw migrationError("UPLOAD_RETRY_EXHAUSTED", "Upload retry limit was exceeded");
};

const updateNoteReferences = async ({
  noteCollection,
  fileId,
  key,
  backups,
  report,
  dryRun,
}) => {
  const cursor = noteCollection.find({ fileId }, { projection: { _id: 1, fileId: 1, s3Key: 1 } });
  for await (const note of cursor) {
    if (note.s3Key) continue;
    ensureOriginalRecordIsBackedUp(backups, "note", note, fileId);
    if (dryRun) continue;
    const result = await noteCollection.updateOne(
      { _id: note._id, fileId, $or: [{ s3Key: { $exists: false } }, { s3Key: null }] },
      { $set: { s3Key: key, storageProvider: "s3" } }
    );
    report.recordsSuccessfullyUpdated += result.modifiedCount;
  }
};

const updatePhotoReferences = async ({
  userCollection,
  fileId,
  key,
  contentType,
  backups,
  report,
  dryRun,
}) => {
  const cursor = userCollection.find(
    { profilePhotoFileId: fileId },
    { projection: { _id: 1, profilePhotoFileId: 1, profilePhotoS3Key: 1 } }
  );
  for await (const user of cursor) {
    if (user.profilePhotoS3Key) continue;
    ensureOriginalRecordIsBackedUp(backups, "user", user, fileId);
    if (dryRun) continue;
    const result = await userCollection.updateOne(
      {
        _id: user._id,
        profilePhotoFileId: fileId,
        $or: [
          { profilePhotoS3Key: { $exists: false } },
          { profilePhotoS3Key: null },
        ],
      },
      { $set: { profilePhotoS3Key: key, profilePhotoContentType: contentType } }
    );
    report.recordsSuccessfullyUpdated += result.modifiedCount;
  }
};

const verifyExistingReference = async (s3, bucket, key, file, contentType) => {
  const existing = await headObject(s3, bucket, key);
  if (!existing) return false;
  if (
    existing.ContentLength !== file.length ||
    existing.ContentType !== contentType
  ) {
    throw migrationError("S3_REFERENCE_MISMATCH", "Existing S3 reference does not match its GridFS file");
  }
  return true;
};

const runMigration = async ({ mode, backupId }) => {
  const bucket = process.env.AWS_S3_BUCKET;
  const region = process.env.AWS_REGION || "ap-south-1";
  if (!process.env.MONGO_URI) {
    throw migrationError("MONGO_URI_MISSING", "MONGO_URI is required");
  }
  if (!bucket) {
    throw migrationError("S3_BUCKET_MISSING", "AWS_S3_BUCKET is required");
  }

  await mongoose.connect(process.env.MONGO_URI);
  const db = mongoose.connection.db;
  const noteCollection = db.collection(Note.collection.name);
  const userCollection = db.collection(User.collection.name);
  const noteFilesCollection = db.collection("noteFiles.files");
  const photoFilesCollection = db.collection("profilePhotos.files");

  if (mode === "backup") {
    const id = `${new Date().toISOString().replace(/[-:.TZ]/g, "")}_${process.pid}`;
    const backup = await createBackup(db, noteCollection, userCollection, id);
    console.log(JSON.stringify({
      status: "backup_complete",
      backupId: id,
      backupCollection: backup.name,
      noteRecords: backup.notes,
      userRecords: backup.users,
    }, null, 2));
    return;
  }

  const s3 = new S3Client({ region });
  const report = createReport(mode);
  const runId = `${new Date().toISOString().replace(/[-:.TZ]/g, "")}_${process.pid}`;
  await mkdir(REPORT_DIRECTORY, { recursive: true });
  const reportPath = path.join(REPORT_DIRECTORY, `migration-report-${runId}.json`);
  const logPath = path.join(REPORT_DIRECTORY, `migration-log-${runId}.jsonl`);
  const noteRecords = await scanRecords(
    noteCollection,
    { fileId: "fileId", s3Key: "s3Key", contentType: "contentType" },
    report,
    "note"
  );
  const userRecords = await scanRecords(
    userCollection,
    {
      fileId: "profilePhotoFileId",
      s3Key: "profilePhotoS3Key",
      contentType: "profilePhotoContentType",
    },
    report,
    "user"
  );
  const noteFiles = await scanGridFsFiles(noteFilesCollection);
  const photoFiles = await scanGridFsFiles(photoFilesCollection);
  const localPaths = [
    ...(await scanLocalPathReferences(
      noteCollection,
      ["filePath", "fileUrl", "storagePath", "localPath", "path"],
      "note"
    )),
    ...(await scanLocalPathReferences(
      userCollection,
      ["profilePhotoPath", "photoPath", "avatarPath", "profilePhotoUrl", "photoUrl"],
      "user"
    )),
  ];
  const localFiles = await scanLocalStorageFiles(LOCAL_STORAGE_DIRECTORY);
  report.totalGridFsFilesFound = noteFiles.length + photoFiles.length;
  report.totalProfilePhotosFound = photoFiles.length;
  report.localStorageFilesFound = localFiles.length;
  report.totalPdfFilesFound = [...noteFiles, ...photoFiles].filter(
    (file) =>
      file.contentType === "application/pdf" ||
      file.metadata?.contentType === "application/pdf" ||
      /\.pdf$/i.test(file.filename || "")
  ).length;
  report.unresolvedLocalPaths = [...localPaths, ...localFiles];

  if (mode === "apply" && report.unresolvedLocalPaths.length) {
    report.completedAt = new Date().toISOString();
    await recordLog(logPath, {
      status: "blocked_unresolved_local_paths",
      count: report.unresolvedLocalPaths.length,
    });
    await saveReport(reportPath, report);
    console.log(JSON.stringify({
      status: "blocked",
      reportPath,
      unresolvedLocalPaths: report.unresolvedLocalPaths.length,
    }, null, 2));
    throw migrationError(
      "UNRESOLVED_LOCAL_PATHS",
      "Apply stopped: legacy local file-path references were found; configure a source root and migrate those paths separately"
    );
  }

  let backups;
  if (mode === "apply") {
    backups = await readBackup(db, backupId);
  }

  const noteRecordsByFileId = new Map();
  for (const note of noteRecords) {
    if (!note.fileId) continue;
    const id = String(note.fileId);
    if (!noteRecordsByFileId.has(id)) noteRecordsByFileId.set(id, []);
    noteRecordsByFileId.get(id).push(note);
  }
  const photoRecordsByFileId = new Map();
  for (const user of userRecords) {
    if (!user.profilePhotoFileId) continue;
    const id = String(user.profilePhotoFileId);
    if (!photoRecordsByFileId.has(id)) photoRecordsByFileId.set(id, []);
    photoRecordsByFileId.get(id).push(user);
  }

  const processFiles = async (files, sourceBucket, recordsByFileId, kind) => {
    const filesById = new Map(files.map((file) => [String(file._id), file]));
    console.log(`[migration] Starting ${kind} files: ${files.length}`);
    for (const [fileId, records] of recordsByFileId) {
      if (!filesById.has(fileId) && records.some((record) =>
        kind === "note" ? !record.s3Key : !record.profilePhotoS3Key
      )) {
        const missing = { kind, fileId, recordIds: records.map((record) => String(record._id)) };
        report.missingOrInaccessibleFiles.push(missing);
        await recordLog(logPath, { status: "missing_source", ...missing });
      }
    }

    for (const [fileIndex, file] of files.entries()) {
      console.log(`[migration] ${kind} file ${fileIndex + 1}/${files.length}`);
      const records = recordsByFileId.get(String(file._id)) || [];
      const fileKey = getObjectKey(sourceBucket, file);
      const contentType = getContentType(
        file,
        records,
        kind === "note" ? "contentType" : "profilePhotoContentType"
      );
      const linkedButAlreadyMigrated = records.length > 0 && records.every((record) =>
        kind === "note" ? Boolean(record.s3Key) : Boolean(record.profilePhotoS3Key)
      );
      try {
        const unmigratedReferences = records.filter((record) =>
          kind === "note" ? !record.s3Key : !record.profilePhotoS3Key
        );
        if (kind === "note" && unmigratedReferences.length > 1) {
          throw migrationError(
            "SHARED_NOTE_FILE_REFERENCE",
            "Multiple notes share one GridFS file, but MongoDB requires unique S3 keys"
          );
        }
        const checksum = await calculateGridFsChecksum(file._id, sourceBucket);
        if (linkedButAlreadyMigrated) {
          for (const record of records) {
            const referenceKey = kind === "note" ? record.s3Key : record.profilePhotoS3Key;
            const exists = await verifyExistingReference(s3, bucket, referenceKey, file, contentType);
            if (!exists)             throw migrationError("S3_REFERENCE_MISSING", "An existing MongoDB S3 reference is missing from S3");
          }
          report.skippedOrDuplicateFiles += 1;
          report.filesVerified += 1;
          await recordLog(logPath, { kind, fileId: String(file._id), status: "already_migrated" });
          await saveReport(reportPath, report);
          continue;
        }

        if (mode === "dry-run") {
          const existing = await headObject(s3, bucket, fileKey);
          if (existing) {
            if (
              !verifyObject(existing, file, contentType, sourceBucket, true) ||
              (await getS3ObjectChecksum(s3, bucket, fileKey)) !== checksum
            ) {
              throw migrationError("S3_OBJECT_CONFLICT", "An existing S3 object conflicts with the migration file");
            }
            report.skippedOrDuplicateFiles += 1;
            report.filesVerified += 1;
          }
          await recordLog(logPath, {
            kind,
            fileId: String(file._id),
            status: existing ? "verified_existing" : "would_upload",
          });
          report.recordsWouldBeUpdated += records.filter((record) =>
            kind === "note" ? !record.s3Key : !record.profilePhotoS3Key
          ).length;
          await saveReport(reportPath, report);
          continue;
        }

        if (mode === "apply") {
          for (const record of records) {
            const keyField = kind === "note" ? "s3Key" : "profilePhotoS3Key";
            if (!record[keyField]) {
              ensureOriginalRecordIsBackedUp(backups, kind, record, file._id);
            }
          }
        }
        const status = await uploadGridFsFile({
          s3,
          bucket,
          sourceBucket,
          file,
          contentType,
          checksum,
          key: fileKey,
          report,
        });
        if (kind === "note") {
          await updateNoteReferences({
            noteCollection,
            fileId: file._id,
            key: fileKey,
            backups,
            report,
            dryRun: false,
          });
        } else {
          await updatePhotoReferences({
            userCollection,
            fileId: file._id,
            key: fileKey,
            contentType,
            backups,
            report,
            dryRun: false,
          });
        }
        await recordLog(logPath, { kind, fileId: String(file._id), status });
      } catch (error) {
        const failure = {
          kind,
          fileId: String(file._id),
          errorCode: getErrorCode(error),
        };
        report.failedUploads.push(failure);
        if (error?.code === "GRIDFS_SOURCE_READ_FAILED") {
          report.missingOrInaccessibleFiles.push({
            kind,
            fileId: String(file._id),
            reason: "gridfs_source_unreadable",
          });
        }
        await recordLog(logPath, { status: "failed", ...failure });
      }
      await saveReport(reportPath, report);
    }
  };

  await processFiles(noteFiles, "noteFiles", noteRecordsByFileId, "note");
  await processFiles(photoFiles, "profilePhotos", photoRecordsByFileId, "photo");
  report.completedAt = new Date().toISOString();
  await saveReport(reportPath, report);
  console.log(JSON.stringify({
    status: report.failedUploads.length || report.missingOrInaccessibleFiles.length
      ? "completed_with_issues"
      : "completed",
    reportPath,
    logPath,
    counts: {
      totalMongoRecordsIdentified: report.totalMongoRecordsIdentified,
      totalPdfFilesFound: report.totalPdfFilesFound,
      totalProfilePhotosFound: report.totalProfilePhotosFound,
      totalGridFsFilesFound: report.totalGridFsFilesFound,
      localStorageFilesFound: report.localStorageFilesFound,
      filesSuccessfullyUploaded: report.filesSuccessfullyUploaded,
      filesVerified: report.filesVerified,
      recordsSuccessfullyUpdated: report.recordsSuccessfullyUpdated,
      recordsWouldBeUpdated: report.recordsWouldBeUpdated,
      skippedOrDuplicateFiles: report.skippedOrDuplicateFiles,
      failedUploads: report.failedUploads.length,
      missingOrInaccessibleFiles: report.missingOrInaccessibleFiles.length,
      unresolvedLocalPaths: report.unresolvedLocalPaths.length,
    },
  }, null, 2));
  if (report.failedUploads.length || report.missingOrInaccessibleFiles.length) {
    process.exitCode = 1;
  }
};

const main = async () => {
  const options = parseArguments(process.argv.slice(2));
  await runMigration(options);
};

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main()
    .catch((error) => {
      console.error(JSON.stringify({
        status: "failed",
        errorCode: getErrorCode(error),
        message: "Migration stopped; no credentials or sensitive values are included in this log.",
      }));
      process.exitCode = 1;
    })
    .finally(async () => {
      await mongoose.disconnect();
    });
}
