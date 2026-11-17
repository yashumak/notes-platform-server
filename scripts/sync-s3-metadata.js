import dotenv from "dotenv";
dotenv.config();

import { createHash, randomUUID } from "node:crypto";
import { appendFile, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  GetObjectCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  S3Client,
} from "@aws-sdk/client-s3";
import mongoose from "mongoose";
import Note from "../models/Note.js";
import User from "../models/User.js";

const SCRIPT_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPORT_DIRECTORY = path.resolve(SCRIPT_DIRECTORY, "..", "migration-reports");
const BACKUP_PREFIX = "noteshub_s3_metadata_backup_";
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
const NOTE_FIELDS = [
  "title",
  "description",
  "fileName",
  "contentType",
  "fileSize",
  "university",
  "course",
  "subject",
  "category",
  "studyType",
  "year",
  "tags",
  "visibility",
  "uploadStatus",
  "createdAt",
  "updatedAt",
  "user_id",
  "s3Key",
  "storageProvider",
  "uploadedBy",
  "s3MetadataId",
  "s3ObjectMetadata",
];
const USER_BACKUP_FIELDS = [
  "_id",
  "profilePhotoS3Key",
  "profilePhotoContentType",
  "profilePhotoS3Metadata",
  "updatedAt",
];

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
const fingerprint = (value) =>
  createHash("sha256").update(String(value)).digest("hex").slice(0, 16);
const normalizeForComparison = (value) => {
  if (value instanceof Date) return value.toISOString();
  if (value instanceof Map) {
    return Object.fromEntries(
      [...value.entries()].sort(([first], [second]) => first.localeCompare(second))
    );
  }
  if (Array.isArray(value)) return value.map(normalizeForComparison);
  if (value?._bsontype === "ObjectId") return String(value);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, normalizeForComparison(value[key])])
    );
  }
  return value ?? null;
};
const sameValue = (left, right) =>
  JSON.stringify(normalizeForComparison(left)) === JSON.stringify(normalizeForComparison(right));
const nonEmpty = (value) =>
  value !== undefined && value !== null && !(typeof value === "string" && !value.trim());

const parseArguments = (args) => {
  const options = { mode: "dry-run", backupId: undefined };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (["--dry-run", "--backup", "--apply", "--verify"].includes(arg)) {
      if (options.mode !== "dry-run" || options.modeExplicit) {
        throw migrationError("INVALID_ARGUMENTS", "Choose exactly one migration mode");
      }
      options.mode = arg.slice(2);
      options.modeExplicit = true;
    } else if (arg === "--backup-id") {
      options.backupId = args[index + 1];
      index += 1;
    } else {
      throw migrationError("INVALID_ARGUMENTS", "Unknown synchronization option");
    }
  }
  if (["apply", "verify"].includes(options.mode) &&
      !/^[a-zA-Z0-9_-]{1,80}$/.test(options.backupId || "")) {
    throw migrationError("BACKUP_REQUIRED", `--${options.mode} requires a backup ID`);
  }
  if (!["apply", "verify"].includes(options.mode) && options.backupId) {
    throw migrationError("INVALID_ARGUMENTS", "--backup-id is only valid with --apply or --verify");
  }
  return options;
};

const retry = async (operation) => {
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt += 1) {
    try {
      return await operation();
    } catch (error) {
      if (attempt === MAX_ATTEMPTS || !isRetryable(error)) throw error;
      await new Promise((resolve) => setTimeout(resolve, 250 * (2 ** (attempt - 1))));
    }
  }
  throw new Error("Unreachable retry state");
};

const appendLog = async (filePath, entry) =>
  appendFile(filePath, `${JSON.stringify({ at: new Date().toISOString(), ...entry })}\n`, "utf8");

const persistReport = async (filePath, report) =>
  writeFile(filePath, `${JSON.stringify(report, null, 2)}\n`, "utf8");

const listAllObjects = async (client, bucket) => {
  const objects = [];
  let continuationToken;
  do {
    const page = await retry(() => client.send(new ListObjectsV2Command({
      Bucket: bucket,
      ContinuationToken: continuationToken,
    })));
    objects.push(...(page.Contents || []).filter((item) => item.Key && !item.Key.endsWith("/")));
    continuationToken = page.IsTruncated ? page.NextContinuationToken : undefined;
  } while (continuationToken);
  return objects;
};

const readJsonObject = async (client, bucket, key) => {
  return retry(async () => {
    const result = await client.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
    if (!result.Body) throw new Error("S3 metadata object has no body");
    return JSON.parse(await result.Body.transformToString());
  });
};

const getObjectHead = async (client, bucket, key) =>
  retry(() => client.send(new HeadObjectCommand({ Bucket: bucket, Key: key })));

const objectMetadata = (bucket, listed, head) => ({
  bucket,
  etag: head.ETag || listed.ETag,
  lastModified: head.LastModified || listed.LastModified,
  storageClass: head.StorageClass || listed.StorageClass || "STANDARD",
  customMetadata: head.Metadata || {},
});

const getMetadataKey = (record) =>
  record?.s3Key || record?.fileKey || record?.objectKey || record?.key || null;

const isNoteMetadataKey = (key) =>
  /^metadata\/[^/]+\.json$/i.test(key) || /^notes\/metadata\/[^/]+\.json$/i.test(key);

const getNoteMetadataId = (key) =>
  key.startsWith("notes/metadata/")
    ? key.slice("notes/metadata/".length, -".json".length)
    : key.slice("metadata/".length, -".json".length);

const getOwnerIdentifier = (record) =>
  record?.uploadedBy || record?.userId || record?.user_id || record?.ownerId || null;

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
  totalPdfFilesFound: 0,
  totalProfilePhotosFound: 0,
  missingS3Objects: 0,
  missingObjectFingerprints: [],
  failedOperations: 0,
  unmatchedObjects: 0,
  unmatchedObjectFingerprints: [],
  unresolvedOwnerIds: 0,
  plan: { notesToInsert: 0, notesToUpdate: 0, notesToSkip: 0, photosToUpdate: 0 },
  warnings: [],
});

const getExistingMaps = (notes, users) => {
  const noteById = new Map();
  const noteByKey = new Map();
  const userByIdentity = new Map();
  for (const note of notes) {
    if (note.s3MetadataId) noteById.set(note.s3MetadataId, note);
    if (note.s3Key) {
      if (noteByKey.has(note.s3Key)) noteByKey.set(note.s3Key, null);
      else noteByKey.set(note.s3Key, note);
    }
  }
  for (const user of users) {
    userByIdentity.set(String(user._id), user);
    if (user.user_id) userByIdentity.set(String(user.user_id), user);
  }
  return { noteById, noteByKey, userByIdentity };
};

const buildNoteUpdate = ({ record, id, key, head, bucket, user, existing }) => {
  const metadata = { ...record };
  const filename = metadata.fileName || metadata.filename || metadata.originalName ||
    existing?.fileName ||
    path.posix.basename(key);
  const date = metadata.createdAt
    ? new Date(metadata.createdAt)
    : existing?.createdAt || head.LastModified;
  const update = {
    s3MetadataId: id,
    s3Key: key,
    storageProvider: "s3",
    uploadedBy: user._id,
    fileName: filename,
    contentType: metadata.contentType || metadata.mimeType || existing?.contentType || head.ContentType ||
      "application/octet-stream",
    fileSize: Number(metadata.fileSize ?? metadata.size ?? existing?.fileSize ?? head.ContentLength),
    visibility: metadata.visibility || existing?.visibility || "public",
    uploadStatus: metadata.uploadStatus || existing?.uploadStatus || "active",
    s3ObjectMetadata: objectMetadata(bucket, {}, head),
  };
  if (nonEmpty(metadata.title)) update.title = metadata.title;
  else update.title = existing?.title ||
    path.posix.basename(filename, path.posix.extname(filename));
  for (const field of ["description", "university", "course", "subject", "category", "studyType", "tags"]) {
    if (nonEmpty(metadata[field])) update[field] = metadata[field];
  }
  if (metadata.user_id) update.user_id = String(metadata.user_id);
  if (metadata.tags && !Array.isArray(metadata.tags)) {
    update.tags = String(metadata.tags).split(",").map((tag) => tag.trim()).filter(Boolean);
  }
  const year = Number(metadata.year);
  if (Number.isFinite(year) && year > 0) update.year = year;
  if (date && Number.isFinite(date.getTime())) update.createdAt = date;
  const updatedAt = metadata.updatedAt
    ? new Date(metadata.updatedAt)
    : existing?.updatedAt || head.LastModified;
  if (updatedAt && Number.isFinite(updatedAt.getTime())) update.updatedAt = updatedAt;
  return update;
};

const inspectS3AndMongo = async ({ client, bucket, logPath, report }) => {
  const listedObjects = await listAllObjects(client, bucket);
  report.totalS3Objects = listedObjects.length;
  const listedByKey = new Map(listedObjects.map((item) => [item.Key, item]));
  const metadataObjects = listedObjects.filter(({ Key }) => isNoteMetadataKey(Key));
  const noteDocuments = [];
  for (const item of metadataObjects) {
    try {
      const record = await readJsonObject(client, bucket, item.Key);
      const id = getNoteMetadataId(item.Key);
      noteDocuments.push({ id, record, metadataObject: item });
    } catch (error) {
      report.failedOperations += 1;
      await appendLog(logPath, {
        operation: "read_metadata",
        keyFingerprint: fingerprint(item.Key),
        errorCode: getErrorCode(error),
      });
    }
  }

  const notes = await Note.find({}).lean();
  const users = await User.find({}).select(
    "_id user_id profilePhotoS3Key profilePhotoContentType profilePhotoS3Metadata"
  ).lean();
  report.totalMongoRecordsIdentified = notes.length + users.length;
  const { noteById, noteByKey, userByIdentity } = getExistingMaps(notes, users);
  const headByKey = new Map();
  const missingKeys = new Set();
  const countMissingKey = (key) => {
    if (!missingKeys.has(key)) {
      missingKeys.add(key);
      report.missingS3Objects += 1;
      report.missingObjectFingerprints.push(fingerprint(key));
    }
  };
  const contentObjects = listedObjects.filter(({ Key }) => !isNoteMetadataKey(Key) && !Key.startsWith("metadata/"));
  for (let offset = 0; offset < contentObjects.length; offset += BATCH_SIZE) {
    const batch = contentObjects.slice(offset, offset + BATCH_SIZE);
    const heads = await Promise.all(batch.map(async (item) => {
      try {
        const head = await getObjectHead(client, bucket, item.Key);
        headByKey.set(item.Key, head);
        return { item, head };
      } catch (error) {
        const missing = error?.$metadata?.httpStatusCode === 404;
        if (missing) countMissingKey(item.Key);
        else report.failedOperations += 1;
        await appendLog(logPath, {
          operation: missing ? "missing_object" : "head_object",
          keyFingerprint: fingerprint(item.Key),
          errorCode: getErrorCode(error),
        });
        return { item, head: null };
      }
    }));
    for (const { item, head } of heads) {
      if (!head) continue;
      if (/\.pdf$/i.test(item.Key) || head.ContentType === "application/pdf") {
        report.totalPdfFilesFound += 1;
      }
      if (item.Key.startsWith("photos/")) report.totalProfilePhotosFound += 1;
    }
  }

  const referencedKeys = new Set();
  const notePlan = [];
  for (const { id, record } of noteDocuments) {
    const key = getMetadataKey(record);
    if (!key) {
      report.unmatchedObjects += 1;
      report.unmatchedObjectFingerprints.push({
        sourceIdFingerprint: fingerprint(id),
        reason: "missing_s3_key",
      });
      continue;
    }
    referencedKeys.add(key);
    const head = headByKey.get(key);
    if (!head) {
      if (!listedByKey.has(key)) countMissingKey(key);
      notePlan.push({ status: "missing", id, key, record });
      continue;
    }
    const rawOwnerIdentifier = getOwnerIdentifier(record);
    const ownerIdentifier = String(rawOwnerIdentifier?._id || rawOwnerIdentifier || "");
    const user = userByIdentity.get(ownerIdentifier);
    if (!user) {
      report.unresolvedOwnerIds += 1;
      report.unmatchedObjects += 1;
      report.unmatchedObjectFingerprints.push({
        sourceIdFingerprint: fingerprint(id),
        keyFingerprint: fingerprint(key),
        reason: "unmapped_owner",
      });
      notePlan.push({ status: "unmatched", id, key, record });
      continue;
    }
    const existing = noteById.get(id) || noteByKey.get(key);
    const update = buildNoteUpdate({ record, id, key, head, bucket, user, existing });
    const status = existing
      ? NOTE_FIELDS.every((field) => sameValue(existing[field], update[field]) || update[field] === undefined)
        ? "skip"
        : "update"
      : "insert";
    notePlan.push({ status, id, key, update, existingId: existing?._id });
  }

  for (const item of contentObjects) {
    if (item.Key.startsWith("notes/") && !referencedKeys.has(item.Key)) {
      report.unmatchedObjects += 1;
      report.unmatchedObjectFingerprints.push({
        keyFingerprint: fingerprint(item.Key),
        reason: "unreferenced_note_object",
      });
    }
  }

  for (const note of notes) {
    if (note.s3Key && !headByKey.has(note.s3Key) && !listedByKey.has(note.s3Key)) {
      countMissingKey(note.s3Key);
    }
  }

  const photoPlan = [];
  const photoVerification = [];
  const referencedPhotos = new Set();
  for (const user of users) {
    const key = user.profilePhotoS3Key;
    if (!key) continue;
    referencedPhotos.add(key);
    const head = headByKey.get(key);
    if (!head) {
      if (!listedByKey.has(key)) countMissingKey(key);
      continue;
    }
    report.existingMongoRecords += 1;
    const metadata = objectMetadata(bucket, listedByKey.get(key) || {}, head);
    const photoRecord = {
      userId: user._id,
      key,
      contentType: head.ContentType,
      metadata: { ...metadata, fileSize: head.ContentLength },
    };
    photoVerification.push(photoRecord);
    if (
      user.profilePhotoS3Metadata?.bucket === metadata.bucket &&
      user.profilePhotoS3Metadata?.etag === metadata.etag &&
      sameValue(user.profilePhotoS3Metadata?.lastModified, metadata.lastModified) &&
      user.profilePhotoS3Metadata?.storageClass === metadata.storageClass &&
      user.profilePhotoS3Metadata?.fileSize === head.ContentLength &&
      sameValue(user.profilePhotoS3Metadata?.customMetadata, metadata.customMetadata) &&
      (!head.ContentType || user.profilePhotoContentType === head.ContentType)
    ) {
      report.recordsSkipped += 1;
    } else {
      photoPlan.push(photoRecord);
    }
  }
  for (const item of contentObjects) {
    if (item.Key.startsWith("photos/") && !referencedPhotos.has(item.Key)) {
      report.unmatchedObjects += 1;
      report.unmatchedObjectFingerprints.push({
        keyFingerprint: fingerprint(item.Key),
        reason: "unreferenced_profile_photo",
      });
    }
  }

  const duplicateMongoKeys = [...noteByKey.entries()].filter(([, value]) => value === null).length;
  const duplicateIds = notes.length - new Set(notes.map((note) => note.s3MetadataId).filter(Boolean)).size;
  report.duplicateRecords = duplicateMongoKeys + duplicateIds;
  report.plan.notesToInsert = notePlan.filter(({ status }) => status === "insert").length;
  report.plan.notesToUpdate = notePlan.filter(({ status }) => status === "update").length;
  report.plan.notesToSkip = notePlan.filter(({ status }) => status === "skip").length;
  report.plan.photosToUpdate = photoPlan.length;
  report.existingMongoRecords += notePlan.filter(({ status }) => status === "skip" || status === "update").length;
  report.recordsSkipped += report.plan.notesToSkip;

  return {
    listedObjects,
    listedByKey,
    notes,
    users,
    notePlan,
    photoPlan,
    photoVerification,
  };
};

const backupCollections = async (backupId) => {
  const collectionName = `${BACKUP_PREFIX}${backupId}`;
  const db = mongoose.connection.db;
  if (await db.listCollections({ name: collectionName }).hasNext()) {
    throw migrationError("BACKUP_EXISTS", "That backup ID already exists; choose a new backup ID");
  }
  const [notes, users] = await Promise.all([
    Note.find({}).lean(),
    User.find({}).select(USER_BACKUP_FIELDS.join(" ")).lean(),
  ]);
  const documents = [
    { type: "manifest", backupId, createdAt: new Date(), noteRecords: notes.length, userRecords: users.length },
    ...notes.map((record) => ({ type: "note", originalId: record._id, snapshot: record })),
    ...users.map((record) => ({ type: "user", originalId: record._id, snapshot: record })),
  ];
  await db.collection(collectionName).insertMany(documents, { ordered: true });
  return { backupId, backupCollection: collectionName, noteRecords: notes.length, userRecords: users.length };
};

const requireCompletedBackup = async (backupId) => {
  const collectionName = `${BACKUP_PREFIX}${backupId}`;
  const collectionExists = await mongoose.connection.db.listCollections({ name: collectionName }).hasNext();
  if (!collectionExists) throw migrationError("BACKUP_NOT_FOUND", "The requested backup collection does not exist");
  const manifest = await mongoose.connection.db.collection(collectionName).findOne({ type: "manifest", backupId });
  if (!manifest) throw migrationError("BACKUP_INCOMPLETE", "The requested backup has no completion manifest");
  return manifest;
};

const ensureUniqueSourceIndex = async () => {
  const duplicates = await Note.collection.aggregate([
    { $match: { s3MetadataId: { $type: "string", $ne: "" } } },
    { $group: { _id: "$s3MetadataId", count: { $sum: 1 } } },
    { $match: { count: { $gt: 1 } } },
    { $limit: 1 },
  ]).toArray();
  if (duplicates.length) {
    throw migrationError("DUPLICATE_SOURCE_IDS", "Duplicate S3 metadata IDs prevent safe synchronization");
  }
  const indexes = await Note.collection.indexes();
  const current = indexes.find((index) =>
    index.key?.s3MetadataId === 1 && index.unique === true && index.sparse === true
  );
  if (current) return;
  if (indexes.some((index) => index.key?.s3MetadataId === 1)) {
    throw migrationError("INCOMPATIBLE_SOURCE_INDEX", "An incompatible s3MetadataId index already exists");
  }
  await Note.collection.createIndex(
    { s3MetadataId: 1 },
    { name: "s3MetadataId_unique_sparse", unique: true, sparse: true }
  );
};

const applyPlan = async ({ plan, client, bucket, logPath, report }) => {
  await ensureUniqueSourceIndex();
  for (let offset = 0; offset < plan.notePlan.length; offset += BATCH_SIZE) {
    const batch = plan.notePlan.slice(offset, offset + BATCH_SIZE);
    for (const item of batch) {
      if (!["insert", "update"].includes(item.status)) continue;
      try {
        const currentHead = await getObjectHead(client, bucket, item.key);
        item.update.s3ObjectMetadata = objectMetadata(bucket, plan.listedByKey.get(item.key) || {}, currentHead);
        const query = item.existingId
          ? { _id: item.existingId }
          : { s3MetadataId: item.id };
        const saved = await retry(() => Note.findOneAndUpdate(
          query,
          {
            $set: item.update,
            ...(!item.existingId ? { $setOnInsert: { _id: new mongoose.Types.ObjectId() } } : {}),
          },
          { new: true, upsert: !item.existingId, runValidators: true, timestamps: false }
        ));
        if (!saved) throw new Error("MongoDB did not return the synchronized note");
        if (item.status === "insert") report.newRecordsInserted += 1;
        else report.existingRecordsUpdated += 1;
        await appendLog(logPath, { operation: item.status, sourceIdFingerprint: fingerprint(item.id) });
      } catch (error) {
        report.failedOperations += 1;
        await appendLog(logPath, {
          operation: "synchronize_note",
          sourceIdFingerprint: fingerprint(item.id),
          errorCode: getErrorCode(error),
        });
      }
    }
  }
  for (let offset = 0; offset < plan.photoPlan.length; offset += BATCH_SIZE) {
    for (const photo of plan.photoPlan.slice(offset, offset + BATCH_SIZE)) {
      try {
        const head = await getObjectHead(client, bucket, photo.key);
        photo.metadata = {
          ...objectMetadata(bucket, plan.listedByKey.get(photo.key) || {}, head),
          fileSize: head.ContentLength,
        };
        const result = await retry(() => User.updateOne(
          { _id: photo.userId, profilePhotoS3Key: photo.key },
          {
            $set: {
              profilePhotoS3Metadata: photo.metadata,
              ...(photo.contentType ? { profilePhotoContentType: photo.contentType } : {}),
            },
          }
        ));
        if (!result.matchedCount) throw new Error("Profile photo owner changed during synchronization");
        report.existingRecordsUpdated += 1;
        await appendLog(logPath, { operation: "update_profile_photo", userIdFingerprint: fingerprint(photo.userId) });
      } catch (error) {
        report.failedOperations += 1;
        await appendLog(logPath, {
          operation: "update_profile_photo",
          userIdFingerprint: fingerprint(photo.userId),
          errorCode: getErrorCode(error),
        });
      }
    }
  }
};

const verifyState = async ({ plan, report }) => {
  for (const item of plan.notePlan) {
    if (!["insert", "update", "skip"].includes(item.status)) continue;
    const found = await Note.findOne({ s3MetadataId: item.id }).select("_id s3Key uploadedBy").lean();
    if (
      !found ||
      found.s3Key !== item.key ||
      (item.existingId && String(found._id) !== String(item.existingId)) ||
      String(found.uploadedBy) !== String(item.update.uploadedBy)
    ) {
      report.failedOperations += 1;
    }
  }
  for (const photo of plan.photoVerification) {
    const query = {
      _id: photo.userId,
      profilePhotoS3Key: photo.key,
      "profilePhotoS3Metadata.bucket": photo.metadata.bucket,
      "profilePhotoS3Metadata.etag": photo.metadata.etag,
    };
    if (photo.contentType) query.profilePhotoContentType = photo.contentType;
    const found = await User.findOne(query).select("_id").lean();
    if (!found) report.failedOperations += 1;
  }
};

const run = async ({ mode, backupId }) => {
  if (!process.env.MONGO_URI) throw migrationError("MONGO_URI_MISSING", "MONGO_URI is required");
  const bucket = process.env.AWS_S3_BUCKET;
  if (!bucket) throw migrationError("S3_BUCKET_MISSING", "AWS_S3_BUCKET is required");
  const region = process.env.AWS_REGION || "ap-south-1";
  await mongoose.connect(process.env.MONGO_URI);
  const client = new S3Client({ region });
  await mkdir(REPORT_DIRECTORY, { recursive: true });
  const runId = `${new Date().toISOString().replace(/[-:.TZ]/g, "")}_${randomUUID().slice(0, 8)}`;
  const reportPath = path.join(REPORT_DIRECTORY, `s3-metadata-report-${runId}.json`);
  const logPath = path.join(REPORT_DIRECTORY, `s3-metadata-log-${runId}.jsonl`);
  const report = createReport(mode);
  try {
    if (mode === "backup") {
      const result = await backupCollections(runId);
      report.completedAt = new Date().toISOString();
      report.backup = result;
      await persistReport(reportPath, report);
      console.log(JSON.stringify({ status: "backup_complete", ...result, reportPath }, null, 2));
      return;
    }
    if (mode === "apply" || mode === "verify") await requireCompletedBackup(backupId);
    const plan = await inspectS3AndMongo({ client, bucket, logPath, report });
    report.skippedOrDuplicateFiles = report.duplicateRecords + report.plan.notesToSkip;
    if (mode === "apply") {
      await applyPlan({ plan, client, bucket, logPath, report });
      await verifyState({ plan, report });
    } else if (mode === "verify") {
      await verifyState({ plan, report });
    }
    report.completedAt = new Date().toISOString();
    await persistReport(reportPath, report);
    console.log(JSON.stringify({
      status: mode === "dry-run" ? "dry_run_complete" : `${mode}_complete`,
      report: {
        mode: report.mode,
        totalS3Objects: report.totalS3Objects,
        totalMongoRecordsIdentified: report.totalMongoRecordsIdentified,
        existingMongoRecords: report.existingMongoRecords,
        newRecordsInserted: report.newRecordsInserted,
        existingRecordsUpdated: report.existingRecordsUpdated,
        recordsSkipped: report.recordsSkipped,
        duplicateRecords: report.duplicateRecords,
        totalPdfFilesFound: report.totalPdfFilesFound,
        totalProfilePhotosFound: report.totalProfilePhotosFound,
        missingS3Objects: report.missingS3Objects,
        failedOperations: report.failedOperations,
        unmatchedObjects: report.unmatchedObjects,
        unresolvedOwnerIds: report.unresolvedOwnerIds,
        plannedChanges: report.plan,
      },
      reportPath,
      errorLogPath: logPath,
    }, null, 2));
  } finally {
    client.destroy();
    await mongoose.disconnect();
  }
};

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
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
