# Backend for Notes Platform

This directory contains the backend services for the Notes Platform application. It is built with Node.js, Express.js, and MongoDB.

## Features

- User Authentication (Registration, Login, Logout, Session Management)
- Authenticated profile updates, including study details and profile photos
- Note file uploads stored in MongoDB GridFS

## Setup

1.  **Install Dependencies**:

    ```bash
    npm install
    ```

2.  **Environment Variables**:
    Create a `.env` file in the `backend` directory with the following variables:

    ```
    PORT=5000
    MONGO_URI=your_mongodb_connection_string
    JWT_SECRET=your_jwt_secret_key
    FRONTEND_URL=http://localhost:3000
    ```

3.  **Run the Application**:
    ```bash
    npm start
    ```

## Production Deployment

This backend is plain Node.js and does not need a compilation step. The `build`
script runs a Node.js syntax check so platforms configured with `npm run build`
can complete their build phase.

For Render (or another Node.js host), configure the service to use this
directory as its root if deploying from the monorepo, then use:

- **Build command**: `npm install && npm run build`
- **Start command**: `npm start`

The build command must install dependencies. Running only `npm run build`
performs the syntax check but does not install packages such as `dotenv`.

Set these backend environment variables in the hosting service:

- `MONGO_URI`: production MongoDB connection string
- `JWT_SECRET`: a strong, private signing secret
- `FRONTEND_URL`: the deployed Vercel origin, for example
  `https://your-app.vercel.app` (no trailing slash)
- `PORT`: only if required by the host; the service also honors the host-provided
  `PORT`

In Vercel, set `NEXT_PUBLIC_BACKEND_URL` to the backend's public base URL,
for example `https://your-service.up.railway.app`, with no trailing slash, and
redeploy the frontend. The frontend's Next.js rewrite forwards `/api/*` requests
to this URL. Do not use `localhost` in production.

## API Endpoints

### Authentication

- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/verify`
- `POST /api/auth/logout`
- `PUT /api/auth/profile` (authenticated multipart update; optional `photo` field)
- `GET /api/auth/profile/photo`

General API traffic is limited to 1,000 requests per IP per 15 minutes. Login
requests have a separate limit of 10 failed attempts per IP per 15 minutes;
successful logins do not count toward that limit.

### Notes

- `POST /api/notes/upload` (authenticated multipart upload; file field: `file`)
- `DELETE /api/notes/:id` (authenticated; deletes only a note uploaded by the current user)
- `GET /api/notes/:id/file` (download a stored note file)

Uploaded content is stored in the MongoDB `noteFiles.files` and
`noteFiles.chunks` GridFS collections. No external object storage is required.
