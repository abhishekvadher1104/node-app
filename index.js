import express from 'express';
import path from 'path';
import fs from 'fs';
import mongoose from 'mongoose';
import { log } from 'console';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

mongoose.connect("mongodb://localhost:27017", {
    dbname: 'login_system',
}).then(() => console.log('database connected'))
    .catch((e) => console.log(e));

const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String
});

const User = mongoose.model('User', userSchema);

const app = express();
app.use(cookieParser());
app.use(express.static(path.join(path.resolve(), 'public')));
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');

const isAuthenticated = async (req, res, next) => {

    const { token } = req.cookies;
    if (token) {
        const decoded = jwt.verify(token, 'abcdef');
        console.log(decoded);

        req.user = await User.findById(decoded._id);
        console.log(req.user);
        next();
    }
    else {
        res.redirect('/login');
    }
};

app.get('/', isAuthenticated, (req, res) => {
    res.render('logout', { name: req.user.name });
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/login', async(req,res)=>{
    const  {email,password} = req.body;
    let user = await User.findOne({email})

    if(!user) return res.redirect('/register');
    // user password nakhyo a and database ma email find karyu teni sathe no password means user.password bey same chhe ke  nai te check karavva
    const isMatch= await bcrypt.compare(password, user.password);
    
    if(!isMatch) return res.render('login',{email,message: 'Incorrect Password' });

    const token = jwt.sign({ _id: user._id }, 'abcdef');
    res.cookie('token', token, {
        httpOnly: true,
        expires: new Date(Date.now() + 60 * 1000)
    });
    res.redirect('/');

})

app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    let user = await User.findOne({ email });

    if (user) {
        return res.redirect('/login');
    }
    const hassedpassword =await bcrypt.hash(password,10);

    user = await User.create({
        name,
        email,
        password:hassedpassword
    });
    const token = jwt.sign({ _id: user._id }, 'abcdef');
    res.cookie('token', token, {
        httpOnly: true,
        expires: new Date(Date.now() + 60 * 1000)
    });
    res.redirect('/login');
})


app.get('/logout', (req, res) => {

    res.cookie('token', null, {
        httpOnly: true,
        expires: new Date(Date.now())
    });
    res.redirect('/');
})



app.listen(4000, () => {
    console.log('server is running on port 4000');
})