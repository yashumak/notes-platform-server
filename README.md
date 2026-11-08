NotesHub – Backend

The backend of NotesHub, an online notes-sharing platform that allows students to upload, browse, search, and download educational resources. This REST API handles authentication, user management, notes management, database operations, and cloud file storage.

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

Project Structure

notes-platform-server/
│
├── config/
│   └── db.js
│
├── controllers/
│   ├── auth.controller.js
│   └── notes.controller.js
│
├── middleware/
│   ├── auth.middleware.js
│   └── upload.middleware.js
│
├── models/
│   ├── User.js
│   └── Note.js
│
├── routes/
│   ├── auth.routes.js
│   └── notes.routes.js
│
├── utils/
│
├── index.js
├── package.json
├── package-lock.json
└── .gitignore

Note: The structure is illustrative. Update it if your actual repository uses different filenames or folders.

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

API Modules

Module| Functionality
Authentication| User registration and login
User Management| Profile and account operations
Notes Management| Upload, retrieve, update, and delete notes
Search and Filters| Search and filter educational resources
File Storage| Cloud file upload and access
Admin Management| Administrative operations (planned)

Database Architecture

MongoDB

Stores:

- User registration details
- Encrypted passwords (hashed)
- User profile information
- Notes information and metadata
- Upload ownership and timestamps

Cloud Object Storage

Stores:

- PDF documents
- Notes and study materials
- Uploaded educational resources

MongoDB stores the file metadata and storage references, while the actual files are stored in cloud object storage.

Deployment

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