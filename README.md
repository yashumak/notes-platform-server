# Backend for Notes Platform

This directory contains the backend services for the Notes Platform application. It is built with Node.js, Express.js, and MongoDB.

## Features

- User Authentication (Registration, Login, Logout, Session Management)
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

## API Endpoints

### Authentication

- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/verify`
- `POST /api/auth/logout`

### Notes

- `POST /api/notes/upload` (authenticated multipart upload; file field: `file`)
- `GET /api/notes/:id/file` (download a stored note file)

Uploaded content is stored in the MongoDB `noteFiles.files` and
`noteFiles.chunks` GridFS collections. No external object storage is required.
