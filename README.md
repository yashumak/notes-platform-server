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
- Private S3 file storage with validated, short-lived presigned upload and
  download URLs
- MongoDB persistence with continued support for existing GridFS notes
- Administrator dashboard and protected tools for managing users, notes,
  media, activity, analytics, and audit logs
- Request validation, rate limiting, security headers, and structured,
  sensitive-data-aware logging

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
├── models/          # AdminAuditLog, Note, User, and UserActivity
├── routes/          # Admin, auth, and notes API routes
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
For local development, provide AWS credentials through the AWS credential
provider chain or in this backend-only `.env` file. Never put AWS credentials
in frontend configuration or commit secrets.

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

| Variable | Required | Description |
|---|---|---|
| `PORT` | No | HTTP port; defaults to `5000` |
| `NODE_ENV` | No | Set to `production` on deployed backend instances |
| `MONGO_URI` | Yes | MongoDB connection string |
| `JWT_SECRET` | Yes | Private signing secret of at least 32 bytes |
| `AUTH_ENCRYPTION_PRIVATE_KEY` | Production | RSA private key (PEM) used only by the backend to decrypt login and registration fields |
| `FRONTEND_URL` | Yes | Exact frontend origin for API CORS |
| `AWS_REGION` | No | S3 region; defaults to `ap-south-1` |
| `AWS_S3_BUCKET` | Yes | Private bucket used for note and profile-photo objects |
| `AWS_ACCESS_KEY_ID` | No | Local IAM user key; omit when using an IAM role |
| `AWS_SECRET_ACCESS_KEY` | No | Local IAM secret; omit when using an IAM role |
| `MAX_NOTE_FILE_SIZE_BYTES` | No | Maximum note upload size in bytes |
| `REDIS_URL` | Production | Private Redis/ElastiCache URL for shared rate-limit state |
| `TRUST_PROXY_HOPS` | No | Exact trusted proxy hop count; defaults to `1` for one AWS load balancer |
| `RATE_LIMIT_*` | No | Per-policy window and request limits; see `middlewares/rateLimiters.js` |

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
