///SSR with authentication using express, bcrypt, jwt and cookie-parser

const express = require('express');
const app=express();
const userModel = require('./models/user');
const postModel = require('./models/post');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');


app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(cookieParser());
app.set('view engine', 'ejs');

const JWT_SECRET = process.env.JWT_SECRET;

app.get('/', (req, res) => {
    res.render('home');
});

app.get('/create', (req, res) => {
    res.render('index');
});

app.get('/feed', isLoggedIn, async (req, res) => {
    const user = await userModel.findById(req.user.userid);
    if (!user) return res.render('notfound'); 
    const posts = await postModel.find().populate('user').sort({ createdAt: -1 });
    res.render('feed', { user, posts });
});


app.get('/profile', isLoggedIn, async (req, res) => {
    let user = await userModel.findOne({ email: req.user.email }).populate("posts");

    if (!user) {
        return res.render('notfound'); 
    }

    res.render('profile', { user });
});


app.get('/like/:id', isLoggedIn, async (req, res) => {
    let post = await postModel.findById(req.params.id);

    if (!post) return res.redirect('/profile');

    const userId = req.user.userid;

    if (post.likes.indexOf(userId) === -1) {
        post.likes.push(userId);
    } else {
        const index = post.likes.indexOf(userId);
        post.likes.splice(index, 1);
    }

    await post.save();
    res.redirect('/profile');
});

app.get('/edit/:id', isLoggedIn, async (req, res) => {
   let post = await postModel.findOne({_id:req.params.id});
   res.render('edit',{post});
});


app.post('/post',isLoggedIn, async(req, res) => {
    let{content} = req.body;
 let user = await userModel.findOne({email:req.user.email});
 let post = await postModel.create({
    user:user._id,
    content: content,
 })
 user.posts.push(post._id);
 await user.save();
    res.redirect('/profile');
});

app.post('/update/:id',isLoggedIn, async(req, res) => {
   
 let post = await postModel.findOneAndUpdate({_id:req.params.id},{content:req.body.content});
    res.redirect('/profile');
});


app.post('/register', async (req, res) => {
    let { password, username, name, email, age } = req.body;

    let found = await userModel.findOne({ email });
    if (found) {
        return res.render('exist'); // ✅ stop here
    }

    bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(password, salt, async (err, hash) => {
            let user = await userModel.create({
                username,
                name,
                age,
                email,
                password: hash,
            });

            let token = jwt.sign(
                { email: email, userid: user._id },JWT_SECRET       
            );

           res.cookie("token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "none"
});

            return res.redirect('/success'); 
        });
    });
});

app.get('/success', (req, res) => {
    res.render('success');
});


app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async(req, res) => {
    let{password,email} = req.body;
    let user = await userModel.findOne({email});
    if(!user) return res.status(404).send('User Not Found');

    let isMatch = await bcrypt.compare(password,user.password);
    if(!isMatch) return res.render('invalid');
    if(isMatch){
        let token = jwt.sign({email:email, userid: user._id},JWT_SECRET);
       
res.cookie("token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "none"
});

res.redirect('/profile');
    }
});

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.render('logout');
});

function isLoggedIn(req, res, next) {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).redirect("/login");
    }

    try {
        const data = jwt.verify(token, JWT_SECRET);
        req.user = data;
        next();
    } catch (err) {
        return res.render('notfound');
    }
}


module.exports = app;

