NotesHub – Backend

The backend of NotesHub, an online notes-sharing platform that allows students to upload, browse, search, and download educational resources. This REST API handles authentication, user management, notes management, database operations, and cloud file storage.

# NotesHub Backend

NotesHub Backend is the REST API for NotesHub, a notes-sharing platform for
students. It provides account and session management, note discovery and
uploads, private file access, and administrator tools.

## Features

- Account registration, login, profile management, and password changes
- JWT-backed authentication with secure, hashed passwords
- Note listing, search, filtering, pagination, upload, and owner-controlled
  deletion
- Guest and signed-in feedback submissions with validation and rate limiting
- Private S3 file storage with validated, short-lived presigned upload and
  download URLs
- MongoDB persistence with continued support for existing GridFS notes
- Administrator dashboard and protected tools for managing users, notes,
  media, activity, analytics, and audit logs
- Request validation, rate limiting, security headers, and structured,
  sensitive-data-aware logging

Feedback is stored in the `feedback` MongoDB collection. Signed-in submissions
include a server-verified user snapshot; guest submissions remain anonymous.
Administrators can view paginated feedback through `GET /api/admin/feedback`.

## Technology

| Technology | Purpose |
| --- | --- |
| Node.js 20+ | JavaScript runtime |
| Express 5 | HTTP API framework |
| MongoDB and Mongoose | Account, activity, and note data |
| AWS S3 SDK | Private note and profile-photo storage |
| JWT and bcrypt | Authentication and password hashing |
| Redis | Shared rate-limit storage in production |

## Project structure

```text
backend/
├── config/          # auth.js, db.js
├── controllers/     # admin, auth, and notes controllers
├── middlewares/     # Authentication, validation, logging, and rate limits
├── models/          # AdminAuditLog, Feedback, Note, User, and UserActivity
├── routes/          # Admin, auth, feedback, and notes API routes
├── scripts/         # seed-admin.js
├── services/        # S3 storage operations
├── test/            # Automated tests
├── utils/           # Shared authentication, logging, and validation helpers
├── index.js         # Express application and server startup
└── package.json     # Scripts and dependencies
```

New note files, note metadata, and profile photos are stored in a private S3
bucket under the top-level `notes/`, `metadata/`, and `photos/` prefixes.
MongoDB stores accounts and authentication data. Existing GridFS notes remain
readable. Legacy GridFS profile photos and S3 photos under the old
`profile-photo/` prefix are moved to `photos/` the first time they are
requested. Existing note metadata under `notes/metadata/` is also still read
during the transition.
Features


- User registration and login
- JWT-based authentication
- Secure password hashing
- User profile management
- Notes upload and management
- Notes metadata management
- Cloud-based document storage
- Search and filter functionality
- Pagination for notes listing
- Protected API endpoints
- Input validation and error handling
- Rate limiting and security middleware

Technology Stack

## Getting started

### Prerequisites

- Node.js 20 or newer and npm
- MongoDB
- An AWS S3 bucket and an AWS identity with the required bucket permissions

### Install and configure

From the backend directory, install dependencies and create a local environment
file:

```powershell
npm install
if (-not (Test-Path .env)) { New-Item .env -ItemType File }
notepad .env
```

Edit `.env` and set at least `MONGO_URI`, `JWT_SECRET` (at least 32 bytes),
`FRONTEND_URL`, and `AWS_S3_BUCKET`. `AWS_REGION` defaults to `ap-south-1`.
The backend uses AWS Secrets Manager if `MONGO_URI` and `JWT_SECRET` are not
both set locally. For local development without AWS access, run MongoDB and set
`MONGO_URI` and a unique `JWT_SECRET` in `.env`; the Admin key endpoint will
return 502 while the Main Backend is unavailable. See `.env.example` for a
local MongoDB URI and a command to generate a suitable JWT secret.
When using AWS Secrets Manager or S3 locally, provide AWS credentials through
the AWS credential provider chain or in this backend-only `.env` file. Never
put AWS credentials in frontend configuration or commit secrets.

For development, `AUTH_ENCRYPTION_PRIVATE_KEY` can be omitted; the backend
generates an ephemeral key pair. Login and registration sessions will not
survive restarting the backend when using that generated key. Production must
use a stable private key configured through the hosting provider's secret
manager. `REDIS_URL` is optional in development, where rate limits use
process-local memory; it is required in production.

Start the development server:

```powershell
npm run dev
```

The API listens on `http://localhost:5000` by default. To run the production
server locally, use `npm start`.

### Available scripts

| Command | Description |
| --- | --- |
| `npm run dev` | Start the development server with Nodemon |
| `npm start` | Start the server |
| `npm run build` | Check `index.js` syntax |
| `npm test` | Run the backend test suite |
| `npm run test:security` | Run security-focused tests |
| `npm run seed:admin` | Create or explicitly promote an administrator |
| `npm run migrate:s3 -- [options]` | Review, back up, or manually migrate legacy GridFS files to S3 |
| `npm run migrate:s3-metadata:dry` | Preview the S3 metadata synchronization |
| `npm run migrate:s3-metadata:backup` | Back up MongoDB note and profile-photo metadata |
| `npm run migrate:s3-metadata -- --backup-id <id>` | Apply the metadata synchronization |
| `npm run verify:s3-metadata -- --backup-id <id>` | Verify the synchronized records |

### Migrate legacy files to S3

The backend already stores new note files and profile photos in the configured
private S3 bucket. Legacy attachments are stored in the `noteFiles` and
`profilePhotos` MongoDB GridFS buckets; MongoDB records are in the `notes` and
`users` collections. The `uploads/notes` local-storage directory is currently
empty, and the active `Note` schema has no local-path field. The migration
script scans MongoDB references, both GridFS buckets, and the local `uploads/`
directory. If local files or recognized legacy path fields are found, apply is
blocked and they are reported rather than guessed at or silently skipped.

Run these commands from the backend directory. The script defaults to a
read-only dry run; it never runs during application startup:

```powershell
npm run migrate:s3 -- --dry-run
npm run migrate:s3 -- --backup
npm run migrate:s3 -- --apply --backup-id <backup-id-from-output>
```

Review the dry-run report and the backup output before applying. The backup is
a new MongoDB collection named
`noteshub_s3_migration_backup_<backup-id>` containing the original file
references and storage-provider fields that may be changed. Do not use
`--apply` without a completed backup ID. Re-running `--apply` with the same
backup ID resumes safely: existing migrated objects are verified and skipped,
and matching MongoDB records are updated without removing their original
GridFS IDs or deleting GridFS data. S3 keys use the existing `notes/` and
`photos/` prefixes and include each original filename. This migration creates
no `metadata/` or `metradata/` objects; it leaves your existing metadata
storage and MongoDB note metadata unchanged, updating only the file references.

The migration uses `AWS_S3_BUCKET`, `AWS_REGION` (default
`ap-south-1`), `MONGO_URI`, and the AWS SDK credential provider chain. Use an
IAM role where available, or supply credentials through the normal AWS
environment/credential provider mechanism; never add credentials to source
control or logs. The migration identity needs read access to MongoDB, write
access to the backup collection, `s3:GetObject` and `s3:PutObject` on the
bucket's `notes/*` and `photos/*` keys, and permission to inspect object
headers. Grant `s3:ListBucket` only for those key prefixes so the script can
distinguish missing objects from denied reads. Objects are conditionally
created, encrypted with SSE-S3, and checked for length, content type,
encryption, and SHA-256 checksum before MongoDB pointers are changed. Failed
uploads are retried; per-item logs and reports are written to
`migration-reports/`. Missing GridFS sources and unresolved legacy paths are
reported instead of silently skipped. The script does not delete MongoDB
records, GridFS files, existing S3 objects, authentication data, or passwords.

### Synchronize S3 object metadata into MongoDB

The metadata-only sync uses the existing `notes` and `users` collections. It
does not download file bodies, upload or delete S3 objects, or create a
`metadata` collection. Existing S3 note JSON remains available as a fallback
for records whose owner cannot be mapped safely. Mapped note records are stored
in MongoDB with their original S3 string ID in `s3MetadataId`; MongoDB keeps its
own document `_id`. Profile-photo S3 metadata is stored on the matching user.

Run a read-only inventory first, then create the backup and review it before
applying any changes:

```powershell
npm run migrate:s3-metadata:dry
npm run migrate:s3-metadata:backup
npm run migrate:s3-metadata -- --backup-id <backup-id-from-output>
npm run verify:s3-metadata -- --backup-id <backup-id-from-output>
```

The dry run and reports do not modify MongoDB or S3. The backup contains note
metadata and profile-photo fields only; it excludes authentication fields and
passwords. Apply requires a completed backup ID, may be resumed with that same
ID, checks for duplicate source IDs before creating its sparse unique index,
and uses idempotent updates. Reports and privacy-safe error logs are written to
`migration-reports/`. Objects or owners that cannot be matched are reported and
left unchanged for manual review. The sync uses `MONGO_URI`, `AWS_S3_BUCKET`,
`AWS_REGION` (default `ap-south-1`), and the AWS SDK credential provider chain.

Technology| Purpose
Node.js| JavaScript runtime
Express.js| Backend framework
JavaScript| Backend programming language
MongoDB| Database
Mongoose| MongoDB object modeling
JWT| Authentication
bcrypt / bcryptjs| Password hashing
Multer| File upload handling
AWS SDK (S3)| Cloud object storage integration
Helmet| HTTP security headers
CORS| Cross-origin resource sharing
Express Rate Limit| API rate limiting
Render| Backend deployment

## Project structure

```text
backend/
├── config/          # auth.js, db.js
├── controllers/     # auth, and notes controllers
├── middlewares/     # Authentication, validation, logging, and rate limits
├── models/          # AdminAuditLog, Note, User, and UserActivity
├── routes/          # auth, and notes API routes
├── scripts/         # seed-admin.js
├── services/        # S3 storage operations
├── test/            # Automated tests
├── utils/           # Shared authentication, logging, and validation helpers
├── index.js         # Express application and server startup
└── package.json     # Scripts and dependencies
```
Getting Started


1. Clone the repository

git clone https://github.com/yashumak/notes-platform-server.git
cd notes-platform-server

2. Install dependencies

npm install

3. Configure environment variables

Create a ".env" file in the project root.

4. Start the development server

npm run dev

5. Start the production server

npm start

The backend runs locally at:

http://localhost:5000

## Administrator access

The independent Next.js admin interface is in `../Admin/frontend`, with its
Express BFF in `../Admin/backend`. The BFF proxies to this backend's existing
`/api/admin` API; this backend remains authoritative for admin login, user and
note data, role/status checks, audit logging, MongoDB, and S3. Every protected
request verifies the signed session and reloads the account's role and status
from MongoDB. Only an active `ADMIN` account is accepted. Public registration
and profile updates cannot assign a role. Admin provisioning remains a
Main-Backend-only operation; do not copy database credentials or the admin
models into the BFF.

The Main Backend retains its existing HttpOnly, SameSite=Strict session cookie
and one-hour expiry. The BFF consumes that login response and reissues the
session as a host-only HttpOnly cookie for the Vercel same-origin API rewrite;
it forwards the session token back to this backend for every protected
operation.

Provision the first admin explicitly from the backend directory. Supply the
values through a secure one-time environment/secret mechanism; do not commit
them or place them in frontend configuration. For a new admin, set
`ADMIN_NAME`, `ADMIN_EMAIL`, `ADMIN_PASSWORD` (at least 16 characters),
`ADMIN_UNIVERSITY`, `ADMIN_COURSE`, and `ADMIN_YEAR`, then run:

```powershell
npm run seed:admin
```

To promote an existing user, set `ADMIN_EMAIL` and
`ADMIN_PROMOTE_EXISTING=true`, then run the same command. Existing users are
never promoted unless that explicit flag is set. The script does not reset an
existing password.

User deletion in the panel is recoverable: the account is suspended and
soft-deleted while notes and storage objects are retained. The deleted-users
filter can restore an account. Note deletion is an explicit permanent
operation, marks the record before removing its associated file, and creates a
backend audit record. Private S3 files are accessed only after the admin
session and MongoDB association are verified; downloads use short-lived
presigned URLs or GridFS streams.

`AdminAuditLog` records administrator sign-in and management actions; the admin
API exposes read-only audit queries. `UserActivity` records login outcomes,
logout, account/profile/password events, and note upload/delete/download
events from the point tracking was introduced. It does not fabricate earlier
history. Profile photo file sizes, email verification, moderation queues,
download history before tracking, and editable runtime settings are not
available in the existing data model; the panel does not invent those values.

Supported file formats include PDF, legacy and Open XML Word/PowerPoint/Excel,
plain text, CSV, Markdown, JSON, XML, JPEG, PNG, GIF, and WebP. File extension
and declared MIME type must match, and the backend checks the object's content
signature after upload. The frontend displays byte progress and does not send
the file body through the application server.

API Modules

Module| Functionality
Authentication| User registration and login
User Management| Profile and account operations
Notes Management| Upload, retrieve, update, and delete notes
Search and Filters| Search and filter educational resources
File Storage| Cloud file upload and access
Admin Management| Administrative operations (planned)

Rate limits are centralized in `middlewares/rateLimiters.js`. Initial defaults
are 100 general API requests per IP per minute; 5 login requests per IP per
minute; 5 failed login attempts per normalized account per 15 minutes; 5
signups per IP per minute; 3 password changes per IP per 15 minutes; 10 upload
URL requests per IP per 10 minutes; 30 filtered/search notes requests per IP
per minute; and 60 unfiltered public notes-list requests per IP per minute.
Each window and limit is independently configurable with the corresponding
`RATE_LIMIT_*` environment variables. The specific endpoint policy replaces the general
limiter for that request, rather than stacking duplicate counters.

Database Architecture

MongoDB

Stores:


- User registration details
- Encrypted passwords (hashed)
- User profile information
- Notes information and metadata
- Upload ownership and timestamps

`TRUST_PROXY_HOPS` controls Express's proxy trust setting used to derive client
IP addresses. Set it to the exact number of trusted proxies in front of the
backend (usually `1` for an application reachable only through one AWS ALB).
Do not expose the backend directly to untrusted clients when trusting a proxy,
and do not increase the hop count without matching it to the deployment path.
For Admin BFF traffic, prefer the provider's private service URL so the trusted
client IP forwarded by the BFF remains the Main Backend's proxy hop and
per-IP login limits are not shared across all administrators.
In production the API rejects requests that do not arrive over HTTPS (directly
or through the configured trusted TLS-terminating proxy). Configure TLS at the
public load balancer/hosting edge and set the trusted proxy hop count accurately.
Production MongoDB connections also require TLS with certificate verification.
Production startup requires `AUTH_ENCRYPTION_PRIVATE_KEY`; store the PEM value
in the backend host's secret manager and use the same key across backend
replicas. Its matching public key is intentionally exposed for the existing
RSA-OAEP/AES-256-GCM authentication-payload protocol. Application-level
encryption is not applied to ordinary profile or note metadata; use MongoDB
deployment encryption-at-rest and encrypted backups for those stores. S3
uploads require SSE-S3 (`AES256`), and the bucket must remain private.

Cloud Object Storage

Stores:

- PDF documents
- Notes and study materials
- Uploaded educational resources

MongoDB stores the file metadata and storage references, while the actual files are stored in cloud object storage.


Deployment

The Admin frontend/BFF are deployed independently; configure their
`ADMIN_BFF_URL`, `MAIN_BACKEND_URL`, and `ADMIN_FRONTEND_ORIGINS` as documented
in `../Admin/README.md`. The Admin frontend uses a same-origin rewrite, so
browser traffic reaches the BFF rather than calling this backend directly.

Existing GridFS records and objects are retained and continue to use the
legacy GridFS download path. New uploads use S3. Plan any migration separately;
do not remove GridFS collections until all existing references have been
verified and migrated.

The backend is deployed on Render.

Deployment configuration:

- Build Command: "npm install"
- Start Command: "npm start"
- Environment Variables: Configure them in the Render dashboard.
- Repository: GitHub

Security

- JWT authentication
- Password hashing
- Protected API routes
- Request validation
- CORS configuration
- HTTP security headers
- Rate limiting
- Secure environment variable management
- File upload validation

Future Enhancements

- Admin dashboard and role-based access control
- API documentation using Swagger
- Automated testing
- Advanced caching
- Improved search and filtering
- Performance monitoring
- Scalable file storage architecture

Related Repository

Frontend: Next.js-based NotesHub web application.

Backend: https://github.com/yashumak/notes-platform-server

Author

Yash Umak

- GitHub: https://github.com/yashumak
- Portfolio: https://yashumak.me
- LinkedIn: https://linkedin.com/in/yashumak

License

This project is intended for educational and development purposes. Add a LICENSE file to define the terms of use.
