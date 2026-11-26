import {
  DeleteObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import mongoose from "mongoose";
import Note from "../models/Note.js";
import User from "../models/User.js";
import { hasValidFileSignature, sanitizeFileName } from "../utils/fileValidation.js";
import { getAppSecrets } from "../config/secrets.js";

export const UPLOAD_URL_TTL_SECONDS = 300;
export const DOWNLOAD_URL_TTL_SECONDS = 120;
const SIGNATURE_CHECK_BYTES = 4096;

let client;
let configuredRegion;

const getStorageConfig = () => {
  const secrets = getAppSecrets();
  const region = secrets.awsRegion || process.env.AWS_REGION || "ap-south-1";
  const bucket = secrets.s3Bucket || process.env.AWS_S3_BUCKET;
  if (!bucket) {
    const error = new Error("S3 storage is not configured");
    error.code = "S3_CONFIGURATION_MISSING";
    throw error;
  }
  if (!client || configuredRegion !== region) {
    const credentials =
      secrets.awsAccessKeyId && secrets.awsSecretAccessKey
        ? {
            accessKeyId: secrets.awsAccessKeyId,
            secretAccessKey: secrets.awsSecretAccessKey,
            ...(secrets.awsSessionToken ? { sessionToken: secrets.awsSessionToken } : {}),
          }
        : undefined;
    client = new S3Client({ region, ...(credentials ? { credentials } : {}) });
    configuredRegion = region;
  }
  return { client, bucket };
};

const formatContentDisposition = (fileName) => {
  const safeName = sanitizeFileName(fileName);
  const asciiName = safeName.replace(/[^\x20-\x7e]/g, "_").replace(/["\\]/g, "_");
  const encodedName = encodeURIComponent(safeName).replace(/[!'()*]/g, (character) =>
    `%${character.charCodeAt(0).toString(16).toUpperCase()}`
  );
  return `attachment; filename="${asciiName}"; filename*=UTF-8''${encodedName}`;
};

const invalidUploadError = () => {
  const error = new Error("Uploaded file did not match its validated metadata");
  error.code = "INVALID_S3_UPLOAD";
  return error;
};

const serializeStoredNote = (record) => {
  if (!record) return null;
  const note = typeof record.toObject === "function" ? record.toObject() : record;
  return { ...note, _id: String(note.s3MetadataId || note._id) };
};

const saveNoteRecord = async (note) => {
  const sourceId = String(note.s3MetadataId || note._id || "");
  const ownerId = String(note.uploadedBy || "");
  if (!sourceId || !note.s3Key || !mongoose.isValidObjectId(ownerId)) {
    return null;
  }
  if (!(await User.exists({ _id: ownerId }))) return null;

  const existing = await Note.findOne({
    $or: [{ s3MetadataId: sourceId }, { s3Key: note.s3Key }],
  }).lean();
  if (existing && existing.s3MetadataId && existing.s3MetadataId !== sourceId) {
    const error = new Error("S3 object key is already associated with another note");
    error.code = "S3_METADATA_CONFLICT";
    throw error;
  }

  const fields = [
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
  ];
  const update = {
    s3MetadataId: sourceId,
    s3Key: note.s3Key,
    storageProvider: "s3",
    uploadedBy: new mongoose.Types.ObjectId(ownerId),
    s3ObjectMetadata: {
      ...(note.s3ObjectMetadata || {}),
      bucket: note.s3ObjectMetadata?.bucket || (await getStorageConfig()).bucket,
    },
  };
  for (const field of fields) {
    if (note[field] !== undefined) update[field] = note[field];
  }

  const saved = await Note.findOneAndUpdate(
    existing ? { _id: existing._id } : { s3Key: note.s3Key },
    {
      $set: update,
      ...(!existing ? { $setOnInsert: { _id: new mongoose.Types.ObjectId() } } : {}),
    },
    { new: true, upsert: !existing, runValidators: true, timestamps: false }
  ).lean();
  return serializeStoredNote(saved);
};

export const s3Storage = {
  async createUploadUrl({ key, contentType, fileSize }) {
    const { client: s3Client, bucket } = getStorageConfig();
    const command = new PutObjectCommand({
      Bucket: bucket,
      Key: key,
      ContentLength: fileSize,
      ContentType: contentType,
      ServerSideEncryption: "AES256",
    });
    return getSignedUrl(s3Client, command, { expiresIn: UPLOAD_URL_TTL_SECONDS });
  },

  async verifyUploadedObject({ key, contentType, fileSize }) {
    const { client: s3Client, bucket } = getStorageConfig();
    const head = await s3Client.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));

    if (
      head.ContentLength !== fileSize ||
      head.ContentType !== contentType ||
      head.ServerSideEncryption !== "AES256"
    ) {
      throw invalidUploadError();
    }

    const result = await s3Client.send(
      new GetObjectCommand({
        Bucket: bucket,
        Key: key,
        Range: `bytes=0-${Math.min(fileSize, SIGNATURE_CHECK_BYTES) - 1}`,
      })
    );
    if (!result.Body) throw invalidUploadError();
    const bytes = Buffer.from(await result.Body.transformToByteArray());
    if (!hasValidFileSignature({ buffer: bytes, contentType })) throw invalidUploadError();
    return {
      bucket,
      etag: head.ETag,
      lastModified: head.LastModified,
      storageClass: head.StorageClass || "STANDARD",
      customMetadata: head.Metadata || {},
    };
  },

  async createDownloadUrl({ key, fileName, contentType }) {
    const { client: s3Client, bucket } = getStorageConfig();
    return getSignedUrl(
      s3Client,
      new GetObjectCommand({
        Bucket: bucket,
        Key: key,
        ResponseContentDisposition: formatContentDisposition(fileName),
        ResponseContentType: contentType || "application/octet-stream",
        ResponseCacheControl: "private, no-store",
      }),
      { expiresIn: DOWNLOAD_URL_TTL_SECONDS }
    );
  },

  async putProfilePhoto({ key, body, contentType }) {
    const { client: s3Client, bucket } = getStorageConfig();
    await s3Client.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: key,
        Body: body,
        ContentType: contentType,
        CacheControl: "private, no-store",
        ServerSideEncryption: "AES256",
      })
    );
    const head = await s3Client.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
    return {
      bucket,
      etag: head.ETag,
      lastModified: head.LastModified,
      storageClass: head.StorageClass || "STANDARD",
      fileSize: head.ContentLength,
      customMetadata: head.Metadata || {},
    };
  },

  async getProfilePhoto({ key }) {
    const { client: s3Client, bucket } = getStorageConfig();
    const result = await s3Client.send(
      new GetObjectCommand({ Bucket: bucket, Key: key })
    );
    if (!result.Body) throw new Error("S3 profile photo object is empty");
    return {
      body: Buffer.from(await result.Body.transformToByteArray()),
      contentType: result.ContentType,
    };
  },

  async createProfilePhotoUrl({ key, contentType }) {
    const { client: s3Client, bucket } = getStorageConfig();
    return getSignedUrl(
      s3Client,
      new GetObjectCommand({
        Bucket: bucket,
        Key: key,
        ResponseContentDisposition: "inline",
        ResponseContentType: contentType,
        ResponseCacheControl: "private, no-store",
      }),
      { expiresIn: DOWNLOAD_URL_TTL_SECONDS }
    );
  },

  async listBucketObjectPage({ continuationToken, limit }) {
    const { client: s3Client, bucket } = getStorageConfig();
    const response = await s3Client.send(new ListObjectsV2Command({
      Bucket: bucket,
      MaxKeys: limit,
      ...(continuationToken ? { ContinuationToken: continuationToken } : {}),
    }));
    const nextToken = response.IsTruncated ? response.NextContinuationToken : undefined;
    if (response.IsTruncated && !nextToken) {
      throw new Error("S3 returned a truncated object page without a continuation token");
    }
    return {
      bucketName: bucket,
      objects: (response.Contents || [])
        .filter((object) => typeof object.Key === "string")
        .map((object) => ({
          s3Key: object.Key,
          sizeBytes: Number.isSafeInteger(object.Size) ? object.Size : null,
          lastModified: object.LastModified instanceof Date
            ? object.LastModified.toISOString()
            : null,
          eTag: typeof object.ETag === "string" ? object.ETag : null,
          storageClass: typeof object.StorageClass === "string"
            ? object.StorageClass
            : "STANDARD",
        })),
      nextToken: nextToken || null,
    };
  },

  async createBucketObjectDownloadUrl(key) {
    if (typeof key !== "string" || !key || Buffer.byteLength(key, "utf8") > 1024) {
      throw new Error("Invalid S3 object key");
    }
    const { client: s3Client, bucket } = getStorageConfig();
    const fileName = key.split("/").pop() || "download";
    return getSignedUrl(
      s3Client,
      new GetObjectCommand({
        Bucket: bucket,
        Key: key,
        ResponseContentDisposition: formatContentDisposition(fileName),
        ResponseCacheControl: "private, no-store",
      }),
      { expiresIn: DOWNLOAD_URL_TTL_SECONDS }
    );
  },

  async deleteObject(key) {
    const { client: s3Client, bucket } = getStorageConfig();
    await s3Client.send(new DeleteObjectCommand({ Bucket: bucket, Key: key }));
  },

  async putNoteRecord(note) {
    return saveNoteRecord(note);
  },

  async getNoteRecord(id) {
    if (typeof id !== "string") return null;
    const alternatives = [{ s3MetadataId: id }];
    if (mongoose.isValidObjectId(id)) alternatives.push({ _id: id });
    const record = await Note.findOne({ $or: alternatives }).lean();
    return serializeStoredNote(record);
  },

  async listNoteRecords() {
    const records = await Note.find({
      uploadStatus: { $ne: "deleting" },
    }).lean();
    return records.map(serializeStoredNote);
  },

  async listNoteRecordPage({ offset, limit }) {
    const [records, total] = await Promise.all([
      Note.find({ uploadStatus: { $ne: "deleting" } })
        .sort({ createdAt: -1 })
        .skip(offset)
        .limit(limit)
        .lean(),
      Note.countDocuments({ uploadStatus: { $ne: "deleting" } }),
    ]);
    return {
      records: records.map(serializeStoredNote),
      total,
    };
  },

  async listNoteRecordsForUser({ uploadedBy }) {
    const records = await Note.find({
      uploadedBy,
      uploadStatus: { $ne: "deleting" },
    }).lean();
    return records.map(serializeStoredNote);
  },

  async deleteNoteRecord(id, { uploadedBy } = {}) {
    if (typeof id !== "string") throw new Error("Invalid note record ID");
    const alternatives = [{ s3MetadataId: id }];
    if (mongoose.isValidObjectId(id)) alternatives.push({ _id: id });
    await Note.deleteOne({ $or: alternatives });
  },
};
