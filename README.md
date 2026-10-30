# NotesHub backend

The backend uses Node.js, Express, MongoDB, and S3. New note files, note
metadata, and profile photos are stored in the private S3 bucket under the
top-level `notes/`, `metadata/`, and `photos/` prefixes. MongoDB remains in use
for accounts and authentication. Existing GridFS notes remain readable. Legacy
GridFS profile photos and S3 photos under the old `profile-photo/` prefix are
moved to `photos/` the first time they are requested. Existing note metadata
under `notes/metadata/` is also still read during the transition.

New S3 keys use a normalized account name and 10-digit user ID for the folder,
then a normalized note title and user ID followed by a unique UUID. For
example: `notes/example-user-1234567890/course-notes-1234567890-<uuid>` and
`metadata/course-notes-1234567890-<uuid>.json`. Profile photos use
`photos/username-user_id`, for example `photos/jane-doe-1234567890`; replacing
a photo updates that user's object.

## Local setup

Install dependencies and copy `.env.example` to `.env`. Set the MongoDB and JWT
values. Set `AWS_REGION` and `AWS_S3_BUCKET`; for local development, provide an
IAM user key pair in the backend `.env`. Never put AWS variables in the
frontend environment or commit real credentials.

The AWS SDK uses its default credential provider chain. On AWS, prefer an
instance/task role and omit `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.
For local development, use a dedicated IAM user restricted to this bucket and
the `notes/*`, `metadata/*`, `notes/metadata/*`, `photos/*`, and legacy
`profile-photo/*` object prefixes.

`MAX_NOTE_FILE_SIZE_BYTES` configures the maximum note size (default: 50 MiB,
maximum supported by S3 single-PUT uploads: 5 GB).

Run the backend with `npm start` or `npm run dev`. The backend expects the
following values:

| Variable | Required | Description |
|---|---|---|
| `PORT` | No | HTTP port; defaults to `5000` |
| `MONGO_URI` | Yes | MongoDB connection string |
| `JWT_SECRET` | Yes | Private signing secret of at least 32 bytes |
| `FRONTEND_URL` | Yes | Exact frontend origin for API CORS |
| `AWS_REGION` | No | S3 region; defaults to `ap-south-1` |
| `AWS_S3_BUCKET` | Yes | Private bucket used for note and profile-photo objects |
| `AWS_ACCESS_KEY_ID` | No | Local IAM user key; omit when using an IAM role |
| `AWS_SECRET_ACCESS_KEY` | No | Local IAM secret; omit when using an IAM role |
| `MAX_NOTE_FILE_SIZE_BYTES` | No | Maximum note upload size in bytes |

## S3 setup

1. Create a bucket in `ap-south-1` (or set the selected region in the backend).
2. Keep **Block all public access** enabled and **Object Ownership: Bucket
   owner enforced**. Do not add a public bucket policy or public ACL.
3. Enable default server-side encryption (SSE-S3/AES-256). Uploads also require
   the signed `x-amz-server-side-encryption: AES256` request header.
4. Configure bucket CORS for the exact deployed frontend origin. For local
   development, add `http://localhost:3000`; replace/add the production origin
   as appropriate:

   ```json
   [
     {
       "AllowedOrigins": ["http://localhost:3000"],
       "AllowedMethods": ["PUT"],
       "AllowedHeaders": ["*"],
       "ExposeHeaders": ["ETag"],
       "MaxAgeSeconds": 3000
     }
   ]
   ```

   Allowing request headers is necessary because the AWS SDK adds a signed
   checksum header to presigned uploads. Restrict `AllowedOrigins` to the exact
   frontend origin; do not use `*` for origins. Add the deployed HTTPS origin
   when deploying the frontend.

5. Grant the backend identity only the following bucket listing and object
   operations. Replace the bucket name. Listing is restricted to current and
   legacy note metadata prefixes; this policy does not grant public access:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"],
         "Resource": [
           "arn:aws:s3:::your-bucket-name/notes/*",
           "arn:aws:s3:::your-bucket-name/metadata/*",
           "arn:aws:s3:::your-bucket-name/notes/metadata/*",
           "arn:aws:s3:::your-bucket-name/photos/*",
           "arn:aws:s3:::your-bucket-name/profile-photo/*"
         ]
       },
       {
          "Effect": "Allow",
          "Action": "s3:ListBucket",
          "Resource": "arn:aws:s3:::your-bucket-name",
          "Condition": {
            "StringLike": {
              "s3:prefix": ["metadata/*", "notes/metadata/*"]
            }
          }
       }
     ]
   }
   ```

The S3 bucket stays private. The API checks each note's visibility before
redirecting to a presigned GET URL that expires after two minutes. Public notes
remain visible and downloadable as before; private notes are visible and
downloadable only by their uploader. Deletion is always restricted to the
uploader. Files are served as attachments with the original safe filename.
Profile photos are returned through the authenticated profile-photo endpoint
using two-minute presigned URLs; the bucket remains private.

## API

- `POST /api/notes/upload/presign` — authenticated; validates filename,
  extension, MIME type, and size; returns a five-minute S3 PUT URL and a
  short-lived, signed upload token. The exact content length is signed into
  the request.
- `POST /api/notes/upload/complete` — authenticated; verifies the uploaded
  object's size, content type, encryption, and file signature before saving a
  JSON note record to S3. It does not create a MongoDB Note document.
- `GET /api/notes/:id/file` — checks public/private access and redirects to a
  two-minute presigned GET URL. Private notes require the uploader's session.
- `POST /api/notes/upload` — deprecated; returns `410 Gone`. Use the two
  presigned upload endpoints instead.
- `GET /api/notes` — public list of shared S3 and legacy notes; private and
  deleting notes are excluded.
- `GET /api/notes/mine` — authenticated list of the current user's notes.
- `DELETE /api/notes/:id` — authenticated; owner-only. S3 note records are
  marked as deleting before object removal so failed deletes can be retried.
- `GET /api/notes/stats` — public note statistics.

Supported file formats include PDF, legacy and Open XML Word/PowerPoint/Excel,
plain text, CSV, Markdown, JSON, XML, JPEG, PNG, GIF, and WebP. File extension
and declared MIME type must match, and the backend checks the object's content
signature after upload. The frontend displays byte progress and does not send
the file body through the application server.

## Deployment

For a backend host such as Render or Railway, use `backend` as the service root,
`npm ci && npm run build` as the build command, and `npm start` as the start
command. The build script performs a syntax check; tests run separately with
`npm test`. Configure MongoDB, JWT, frontend CORS, and S3 variables in the
host's secret/environment settings. MongoDB remains required for accounts and
legacy note compatibility. Attach a least-privilege IAM role where
the host supports roles; otherwise store the IAM key pair only in the backend
host's secret manager.

For the Next.js frontend, set `NEXT_PUBLIC_BACKEND_URL` to the backend's public
base URL and redeploy. Set the backend's `FRONTEND_URL` and the S3 CORS origin
to the frontend's exact HTTPS origin. Never set AWS credentials in Vercel or
any frontend build environment.

Existing GridFS records and objects are retained and continue to use the
legacy GridFS download path. New uploads use S3. Plan any migration separately;
do not remove GridFS collections until all existing references have been
verified and migrated.
