# ðŸ•µï¸ Anonymous â€” Anonymous Messaging App

A full-stack web application that enables users to send and receive messages completely anonymously. Built using Node.js, Express.js, MongoDB, and EJS for server-side rendering.

---

## ðŸš€ Features

- 100% Anonymous messaging (no identity stored)
- Send messages anonymously
- View all submitted messages
- Fast server-side rendering using EJS
- MongoDB database integration
- Clean and modular structure

---

## ðŸ› ï¸ Tech Stack

| Layer | Technology |
|---|---|
| Frontend | EJS, HTML, Tailwind CSS |
| Backend | Node.js, Express.js |
| Database | MongoDB (Mongoose) |
| Tools | Git, npm, dotenv |

---

## ðŸ“ Project Structure

```
anonymous/
â”œâ”€â”€ models/
â”‚   â””â”€â”€ Message.js
â”œâ”€â”€ routes/
â”‚   â””â”€â”€ index.js
â”œâ”€â”€ views/
â”‚   â”œâ”€â”€ index.ejs
â”‚   â”œâ”€â”€ submit.ejs
â”‚   â””â”€â”€ partials/
â”œâ”€â”€ public/
â”‚   â”œâ”€â”€ css/
â”‚   â”œâ”€â”€ js/
â”‚   â””â”€â”€ images/
â”œâ”€â”€ .env
â”œâ”€â”€ app.js
â”œâ”€â”€ package.json
â””â”€â”€ README.md
```

---

## âš™ï¸ Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/your-username/anonymous.git
cd anonymous
```

### 2. Install dependencies

```bash
npm install
```

### 3. Create a `.env` file

```env
PORT=3000
MONGO_URI=your_mongodb_connection_string
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

## ðŸŒ Usage

1. Open your browser and go to: `http://localhost:3000`
2. Submit anonymous messages
3. View messages on the homepage

---

## ðŸ§  How It Works

1. User submits a message through a form
2. Express handles the request
3. Data is stored in MongoDB using Mongoose
4. Server fetches all messages
5. EJS renders them dynamically on the page

---

## ðŸ“Œ API Routes

| Method | Route | Description |
|---|---|---|
| GET | `/` | Show all messages |
| GET | `/submit` | Show submit form |
| POST | `/submit` | Save a new message |

---

## ðŸ”® Future Enhancements

- [ ] Authentication (JWT / OAuth)
- [ ] Spam filtering
- [ ] Like / reaction system
- [ ] Responsive UI improvements
- [ ] Deployment (Render / Railway / Vercel)

---

## ðŸ¤ Contributing

1. Fork the repo
2. Create a branch (`git checkout -b feature-name`)
3. Commit your changes (`git commit -m 'Add feature'`)
4. Push to the branch (`git push origin feature-name`)
5. Open a Pull Request

---


## ðŸ‘¨â€ðŸ’» Author

**Vivek Rakesh Tiwary**  
GitHub: [@vivekcpu](https://github.com/vivekcpu)
Live Demo : https://anonymus-gi0p.onrender.com/
---

## â­ Support

If you like this project, give it a â­ on GitHub â€” it means a lot!
