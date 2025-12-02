// services/storage.service.js
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";

const s3 = new S3Client({
  region: process.env.S3_REGION,
  endpoint: process.env.S3_ENDPOINT,
  credentials: {
    accessKeyId: process.env.S3_ACCESS_KEY_ID,
    secretAccessKey: process.env.S3_SECRET_ACCESS_KEY,
  },
  forcePathStyle: true // important for Backblaze
});

/**
 * Upload buffer to S3-compatible storage (Backblaze B2)
 * @param {Buffer} buffer
 * @param {string} key - path/filename in bucket
 * @param {string} contentType
 * @returns {string} public URL
 */
export async function uploadBufferToS3(buffer, key, contentType = "application/pdf") {
  const bucket = process.env.S3_BUCKET;
  if (!bucket) throw new Error("S3 bucket not configured");

  const params = {
    Bucket: bucket,
    Key: key,
    Body: buffer,
    ContentType: contentType,
    ACL: "public-read" // optional: ensure bucket policy allows public-read OR set bucket public
  };

  await s3.send(new PutObjectCommand(params));

  // Construct public URL. This works with typical S3-compatible endpoint:
  const endpoint = (process.env.S3_ENDPOINT || "").replace(/\/$/, "");
  // Final URL: `${endpoint}/${bucket}/${key}` (works with Backblaze S3 endpoint)
  const url = `${endpoint}/${bucket}/${encodeURIComponent(key)}`;
  return url;
}
