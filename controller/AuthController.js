const express = require('express');
const router = express.Router();
const bodyParser = require('body-parser');
const config = require('../config');
const User = require('../model/userModel');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');


router.use(bodyParser.urlencoded({extended:true}));
router.use(bodyParser.json());

//all users
router.get('/users', async (req,res)=>{
    try {
        const users = await User.find({});
        res.send(users);
    } catch (err) {
        console.error(err);
        res.status(500).send('Error fetching users');
    }
});

//register
router.post('/register', async (req,res)=>{
    try {
        const hashpass = bcrypt.hashSync(req.body.password,8);
        await User.create({
            name:req.body.name,
            email:req.body.email,
            password:hashpass,
            phone:req.body.phone,
            username:req.body.username || 'user'
        });
        res.send("Registered successfully");
    } catch (err) {
        console.error(err);
        res.status(500).send('Error registering user');
    }
});

//login

router.post('/login', async (req,res)=>{
    try {
        const user = await User.findOne({email:req.body.email});
        if (!user) return res.send({auth:false,token:"No user found"});
        const validPass = bcrypt.compareSync(req.body.password,user.password);
        if (!validPass) return res.send({auth:false,token:"Wrong password"});
        const token = jwt.sign({id:user._id},config.secret,{expiresIn:86400});
        res.send({auth:true,token:token});
    } catch (err) {
        console.error(err);
        res.status(500).send('Error logging in');
    }
});


//userinfo

router.get('/userinfo', async (req,res)=>{
    try {
        const token = req.headers['x-access-token'];
        if (!token) return res.send({auth:false,token:"No token provided"});
        jwt.verify(token,config.secret, async (err,user)=>{
            if (err) return res.send({auth:false,token:"Invalid token"});
            const result = await User.findById(user.id);
            res.send(result);
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Error fetching user info');
    }
})

module.exports = router;
