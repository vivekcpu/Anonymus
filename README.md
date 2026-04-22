# Anonymus - Anonymous Messaging App

A full-stack web application that lets users send and receive messages completely anonymously. Features JWT-based authentication, user profiles, a public feed, and full CRUD operations — all wrapped in a clean server-side rendered interface.

Live Demo: https://anonymus-gi0p.onrender.com/

---

## Features

- 100% Anonymous messaging — no sender identity revealed
- JWT-based authentication with secure cookie sessions
- User registration, login, and logout
- Personalized profile page per user
- Public feed of all anonymous messages
- Full CRUD — create, read, update, and delete messages
- Like / reaction system on messages
- Password hashing with bcrypt
- Server-side rendering with EJS
- MongoDB Atlas cloud database integration
- Clean and modular MVC structure

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | EJS, HTML, Tailwind CSS |
| Backend | Node.js, Express.js |
| Database | MongoDB Atlas (Mongoose) |
| Auth | JWT, Cookie-based sessions |
| Security | bcrypt (password hashing) |
| Tools | Git, npm, dotenv |

---

## Project Structure

```
Anonymus/
├── models/
│   ├── post.js
│   └── user.js
├── views/
│   ├── edit.ejs
│   ├── exist.ejs
│   ├── feed.ejs
│   ├── home.ejs
│   ├── index.ejs
│   ├── invalid.ejs
│   ├── login.ejs
│   ├── logout.ejs
│   ├── notfound.ejs
│   ├── profile.ejs
│   └── success.ejs
├── .gitignore
├── app.js
├── package.json
├── package-lock.json
└── README.md
```

---

## Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/vivekcpu/Anonymus.git
cd Anonymus
```

### 2. Install dependencies

```bash
npm install
```

### 3. Create a `.env` file

```env
PORT=3000
MONGO_URI=your_mongodb_atlas_connection_string
JWT_SECRET=your_jwt_secret_key
```

### 4. Run the application

```bash
npm start
```

### 5. Development mode (optional)

```bash
npm run dev
```

---

## Usage

1. Open your browser and go to `http://localhost:3000`
2. Register a new account or log in
3. Submit anonymous messages to the feed
4. View, edit, delete, or like messages
5. Visit your profile to manage your posts

---

## How It Works

1. User registers with a username and password
2. Password is hashed using **bcrypt** before storing in MongoDB
3. On login, a **JWT token** is generated and stored in a secure **cookie**
4. Protected routes verify the JWT on each request
5. Authenticated users can create, edit, delete, and like posts
6. **EJS** templates render all pages server-side dynamically

---

## API Routes

| Method | Route | Description | Auth Required |
|---|---|---|---|
| GET | `/` | Landing page | No |
| GET | `/feed` | View all messages | No |
| GET | `/register` | Register page | No |
| POST | `/register` | Create new user | No |
| GET | `/login` | Login page | No |
| POST | `/login` | Authenticate user | No |
| GET | `/logout` | Log out user | Yes |
| GET | `/profile` | User profile page | Yes |
| POST | `/post` | Create new message | Yes |
| GET | `/edit/:id` | Edit message page | Yes |
| POST | `/edit/:id` | Update message | Yes |
| POST | `/delete/:id` | Delete message | Yes |
| POST | `/like/:id` | Like a message | Yes |

---

## Security

- Passwords are never stored in plain text — bcrypt hashing with salt rounds
- JWT tokens are stored in HTTP-only cookies to prevent XSS attacks
- Protected routes reject unauthenticated requests automatically
- Environment variables keep secrets out of source code

---

## Future Enhancements

- [ ] Real-time messaging with Socket.io
- [ ] Spam / abuse filtering
- [ ] Comment threads on posts
- [ ] Responsive mobile UI
- [ ] Admin dashboard

---

## Contributing

1. Fork the repo
2. Create a branch (`git checkout -b feature-name`)
3. Commit your changes (`git commit -m 'Add feature'`)
4. Push to the branch (`git push origin feature-name`)
5. Open a Pull Request

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Author

**Vivek Rakesh Tiwary**
GitHub: [@vivekcpu](https://github.com/vivekcpu)
Live Demo: https://anonymus-gi0p.onrender.com/

---

If you like this project, give it a star on GitHub - it means a lot!
