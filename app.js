const express = require('express');
const app = express();
const cors = require('cors');
const db = require('./db');
const port = 4500

app.use(cors());

const AuthController = require('./controller/AuthController');

app.use('/api/auth',AuthController);

app.listen(port,(err,result)=>{
            if(err) throw err
            console.log(`server running on ${port}`)
})