import {
  DeleteObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { hasValidFileSignature, sanitizeFileName } from "../utils/fileValidation.js";

export const UPLOAD_URL_TTL_SECONDS = 300;
export const DOWNLOAD_URL_TTL_SECONDS = 120;
const SIGNATURE_CHECK_BYTES = 4096;
const NOTE_METADATA_PREFIX = "metadata/";
const LEGACY_NOTE_METADATA_PREFIX = "notes/metadata/";
const NOTE_METADATA_READ_CONCURRENCY = 25;
const NOTE_ID_PATTERN =
  /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|[a-z0-9 -]{1,220})$/i;

let client;
let configuredRegion;

const getStorageConfig = () => {
  const region = process.env.AWS_REGION || "ap-south-1";
  const bucket = process.env.AWS_S3_BUCKET;
  if (!bucket) {
    const error = new Error("S3 storage is not configured");
    error.code = "S3_CONFIGURATION_MISSING";
    throw error;
  }
  if (!client || configuredRegion !== region) {
    client = new S3Client({ region });
    configuredRegion = region;
  }
  return { client, bucket };
};

const listNoteRecordEntries = async () => {
  const { client: s3Client, bucket } = getStorageConfig();
  const entriesByPrefix = await Promise.all(
    [NOTE_METADATA_PREFIX, LEGACY_NOTE_METADATA_PREFIX].map(async (prefix) => {
      const prefixEntries = [];
      let continuationToken;
      do {
        const page = await s3Client.send(
          new ListObjectsV2Command({
            Bucket: bucket,
            Prefix: prefix,
            ContinuationToken: continuationToken,
          })
        );
        for (const object of page.Contents || []) {
          const id = object.Key?.slice(prefix.length).replace(/\.json$/, "");
          if (!id || !NOTE_ID_PATTERN.test(id)) continue;
          const lastModified = object.LastModified ? new Date(object.LastModified).getTime() : 0;
          prefixEntries.push({ id, lastModified });
        }
        continuationToken = page.IsTruncated ? page.NextContinuationToken : undefined;
      } while (continuationToken);
      return prefixEntries;
    })
  );
  const entries = new Map();
  for (const entry of entriesByPrefix.flat()) {
    const existing = entries.get(entry.id);
    if (!existing || entry.lastModified > existing.lastModified) entries.set(entry.id, entry);
  }
  return [...entries.values()].sort((first, second) => second.lastModified - first.lastModified);
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
    return true;
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

  async deleteObject(key) {
    const { client: s3Client, bucket } = getStorageConfig();
    await s3Client.send(new DeleteObjectCommand({ Bucket: bucket, Key: key }));
  },

  async putNoteRecord(note) {
    const { client: s3Client, bucket } = getStorageConfig();
    await s3Client.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: `${NOTE_METADATA_PREFIX}${note._id}.json`,
        Body: JSON.stringify(note),
        ContentType: "application/json",
        ServerSideEncryption: "AES256",
      })
    );
  },

  async getNoteRecord(id) {
    if (typeof id !== "string" || !NOTE_ID_PATTERN.test(id)) return null;
    const { client: s3Client, bucket } = getStorageConfig();
    for (const prefix of [NOTE_METADATA_PREFIX, LEGACY_NOTE_METADATA_PREFIX]) {
      try {
        const result = await s3Client.send(
          new GetObjectCommand({ Bucket: bucket, Key: `${prefix}${id}.json` })
        );
        if (!result.Body) throw new Error("S3 note metadata object is empty");
        return JSON.parse(await result.Body.transformToString());
      } catch (error) {
        if (error?.name === "NoSuchKey" || error?.$metadata?.httpStatusCode === 404) continue;
        throw error;
      }
    }
    return null;
  },

  async listNoteRecords() {
    const entries = await listNoteRecordEntries();
    const records = [];
    for (let index = 0; index < entries.length; index += NOTE_METADATA_READ_CONCURRENCY) {
      const batch = entries.slice(index, index + NOTE_METADATA_READ_CONCURRENCY);
      const notes = await Promise.all(batch.map(({ id }) => this.getNoteRecord(id)));
      records.push(...notes.filter(Boolean));
    }
    return records;
  },

  async listNoteRecordPage({ offset, limit }) {
    const entries = await listNoteRecordEntries();
    const page = entries.slice(offset, offset + limit);
    const records = await Promise.all(page.map(({ id }) => this.getNoteRecord(id)));
    return {
      records: records.filter(Boolean),
      total: entries.length,
    };
  },

  async deleteNoteRecord(id) {
    if (typeof id !== "string" || !NOTE_ID_PATTERN.test(id)) {
      throw new Error("Invalid S3 note record ID");
    }
    const { client: s3Client, bucket } = getStorageConfig();
    await Promise.all(
      [NOTE_METADATA_PREFIX, LEGACY_NOTE_METADATA_PREFIX].map((prefix) =>
        s3Client.send(
          new DeleteObjectCommand({ Bucket: bucket, Key: `${prefix}${id}.json` })
        )
      )
    );
  },
};
