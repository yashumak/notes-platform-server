# Backend for Notes Platform

This directory contains the backend services for the Notes Platform application. It is built with Node.js, Express.js, and MongoDB.

## Features
- User Authentication (Registration, Login, Logout, Session Management)
- Notes Management (CRUD operations - planned)

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
-   `POST /api/auth/register`
-   `POST /api/auth/login`
-   `GET /api/auth/verify`
-   `POST /api/auth/logout`

### Notes (Planned)
-   `GET /api/notes`
-   `GET /api/notes/:id`
-   `POST /api/notes`
-   `PUT /api/notes/:id`
-   `DELETE /api/notes/:id`
