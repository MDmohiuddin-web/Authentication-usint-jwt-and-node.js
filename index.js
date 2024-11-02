const express = require('express');
const bodyparser = require("body-parser");
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
var cookieParser = require('cookie-parser');
const port = process.env.PORT || 3000;
const app = express();
require('dotenv').config(); 
const bcrypt = require('bcryptjs');
const salt = 10;
app.set('view engine', 'ejs');
app.use(bodyparser.urlencoded({extended:true}));
app.use(express.json());
app.use(cookieParser());
app.use(express.static("public"));

// get our urls and secrets
const JWT_SECRET = process.env.jwt || 'your-secret-key';

// making connection with our database
const connection = mongoose.connect('mongodb://0.0.0.0/Authentication', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => {console.log("connection successful to database")})
.catch(err => console.log("Error connecting to database:", err));

// Schema For User Auth
const userSchema = new mongoose.Schema({
    name: {type: String, required: true},
    email: {type: String, required: true, unique: true},
    password: {type: String, required: true}
}, {collection: 'users'}
)
const User = mongoose.model("User", userSchema);

app.post('/signup', async (req,res) => {
    // getting our data from frontend
    console.log(req.body);
    const { name, email, password: plainTextPassword } = req.body;
    
    if (!name || !email || !plainTextPassword) {
        return res.status(400).json({ status: 'error', error: 'All fields are required' });
    }
    
    // encrypting our password to store in database
    const password = await bcrypt.hash(plainTextPassword, salt);
    try {
        // storing our user data into database
        const response = await User.create({
            name,
            email,
            password
        })
        return res.redirect('/');
    } catch (error) {
        console.log(JSON.stringify(error));
        if(error.code === 11000){
            return res.status(400).json({status: 'error', error: 'email already exists'})
        }
        return res.status(500).json({status: 'error', error: 'Internal server error'})
    }
}) 

// user login function
const verifyUserLogin = async (email, password) => {
    try {
        const user = await User.findOne({email}).lean()
        if(!user){
            return {status: 'error', error: 'user not found'}
        }
        if(await bcrypt.compare(password, user.password)){
            // creating a JWT token
            const token = jwt.sign({id: user._id, username: user.email, type: 'user'}, JWT_SECRET, { expiresIn: '2h'})
            return {status: 'ok', data: token}
        }
        return {status: 'error', error: 'invalid password'}
    } catch (error) {
        console.log(error);
        return {status: 'error', error: 'timed out'}
    }
}

// login 
app.post('/login', async(req, res) => {
    const {email, password} = req.body;
    
    if (!email || !password) {
        return res.status(400).json({status: 'error', error: 'All fields are required'});
    }
    
    // we made a function to verify our user login
    const response = await verifyUserLogin(email, password);
    if(response.status === 'ok'){
        // storing our JWT web token as a cookie in our browser
        res.cookie('token', response.data, { maxAge: 2 * 60 * 60 * 1000, httpOnly: true });  // maxAge: 2 hours
        res.redirect('/');
    }else{
        res.status(401).json(response);
    }
})

const verifyToken = (token) => {
    if(!token) return false;
    try {
        const verify = jwt.verify(token, JWT_SECRET);
        return verify.type === 'user';
    } catch (error) {
        console.log(JSON.stringify(error), "error");
        return false;
    }
}

// get requests
app.get('/', (req, res) => {
    const {token} = req.cookies;
    if(verifyToken(token)){
        return res.render('home');
    }else{
        res.redirect('/login')
    }
}) 

app.get('/login', (req, res) => {
    res.render('signin');
})

app.get('/signup', (req, res) => {
    res.render('signup')
})

app.listen(port, () => {
    console.log(`Running on port ${port}`); 
})