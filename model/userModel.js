const mongoose = require('mongoose');
const userSchema = new mongoose.Schema({
    name:String,
    email:String,
    password:String,
    phone:Number,
    username:String
});

mongoose.model('users',userSchema);
module.exports = mongoose.model('users');