Authentication in Node.js with MongoDB, bcrypt, and JWT web Tokens with cookies 🍪.
Adding authentication to an application is one of the most challenging 😖 but also a very important part for developers
Thats why i make this 



"dependencies": {
    "bcryptjs": "^2.4.3",
    "body-parser": "^1.20.3",
    "cookie-parser": "^1.4.7",
    "dotenv": "^16.4.5",
    "ejs": "^3.1.10",
    "express": "^4.21.1",
    "jsonwebtoken": "^9.0.2",
    "mongodb": "^6.10.0",
    "mongoose": "^8.8.0",
    "nodemon": "^3.1.7"
  }



  project-folder/
├── config/
│   └── database.js
├── controllers/
│   └── authController.js
├── models/
│   └── user.js
├── routes/
│   └── auth.js
├── views/
│   ├── home.ejs
│   ├── signin.ejs
│   └── signup.ejs
├── .env
├── app.js
└── package.json



// config/database.js
const mongoose = require('mongoose');

const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
        console.log('MongoDB connected');
    } catch (err) {
        console.error(err.message);
        process.exit(1);
    }
};

module.exports = connectDB;


// models/user.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
}, { collection: 'users' });

module.exports = mongoose.model('User', userSchema);

// controllers/authController.js
const User = require('../models/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const salt = 10;

const signUp = async (req, res) => {
    const { name, email, password: plainTextPassword } = req.body;
    if (!name || !email || !plainTextPassword) {
        return res.status(400).json({ status: 'error', error: 'All fields are required' });
    }
    const password = await bcrypt.hash(plainTextPassword, salt);
    try {
        const user = await User.create({ name, email, password });
        return res.redirect('/');
    } catch (error) {
        if (error.code === 11000) {
            return res.status(400).json({ status: 'error', error: 'Email already exists' });
        }
        return res.status(500).json({ status: 'error', error: 'Internal server error' });
    }
};

const verifyUserLogin = async (email, password) => {
    try {
        const user = await User.findOne({ email }).lean();
        if (!user) {
            return { status: 'error', error: 'User not found' };
        }
        if (await bcrypt.compare(password, user.password)) {
            const token = jwt.sign({ id: user._id, username: user.email, type: 'user' }, JWT_SECRET, { expiresIn: '2h' });
            return { status: 'ok', data: token };
        }
        return { status: 'error', error: 'Invalid password' };
    } catch (error) {
        return { status: 'error', error: 'Timed out' };
    }
};

const login = async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ status: 'error', error: 'All fields are required' });
    }
    const response = await verifyUserLogin(email, password);
    if (response.status === 'ok') {
        res.cookie('token', response.data, { maxAge: 2 * 60 * 60 * 1000, httpOnly: true });
        res.redirect('/');
    } else {
        res.status(401).json(response);
    }
};

const verifyToken = (token) => {
    if (!token) return false;
    try {
        const verify = jwt.verify(token, JWT_SECRET);
        return verify.type === 'user';
    } catch (error) {
        return false;
    }
};

module.exports = { signUp, login, verifyToken };
// routes/auth.js
const express = require('express');
const { signUp, login, verifyToken } = require('../controllers/authController');

const router = express.Router();

router.post('/signup', signUp);
router.post('/login', login);
router.get('/', (req, res) => {
    const { token } = req.cookies;
    if (verifyToken(token)) {
        return res.render('home');
    } else {
        res.redirect('/login');
    }
});
router.get('/login', (req, res) => {
    res.render('signin');
});
router.get('/signup', (req, res) => {
    res.render('signup');
});

module.exports = router;

// app.js
const express = require('express');
const bodyparser = require('body-parser');
const cookieParser = require('cookie-parser');
const connectDB = require('./config/database');
const authRoutes = require('./routes/auth');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.use(bodyparser.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

// Connect to the database
connectDB();

app.use('/', authRoutes);

app.listen(port, () => {
    console.log(`Running on port ${port}`);
});




















