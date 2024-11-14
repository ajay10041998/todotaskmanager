const express = require('express')
const app = express()
const {open} = require('sqlite')
const sqlite3 = require('sqlite3')
const path = require('path')
const dbPath = path.join(__dirname,'task.db')

const jwt = require('jsonwebtoken')
let db=null
const bcrypt = require('bcrypt')
const {v4:uuidv4} = require('uuid')

app.use(express.json())




const intializeServerAndDb = async () =>{
     try {
        db=await open({
        filename:dbPath,
        driver:sqlite3.Database
    })
    app.listen(3000,()=>{
        console.log("app listening on port 3000")
    })
}
catch(e){
    console.log(`db error ${e.message}`)
    process.exit(1)
}
}

intializeServerAndDb()

//user signup//

app.post('/user/signup',async(req,res)=>{
    const {user_name,user_email,user_password} = req.body 
    try{
        const userSignupQuery = `select * from user where user_email=?`
        const userSignup = await db.get(userSignupQuery,[user_email])
    
    if (userSignup === undefined){
        const hashedPassword = await bcrypt.hash(user_password,10)
        const user_id = uuidv4()
        const userSignupDetailsQuery = `insert into user (user_id,user_name,user_email,user_password) values (?,?,?,?)`
        const userDetailsQuery = await db.run(userSignupDetailsQuery,[user_id,user_name,user_email,hashedPassword])
       res.status(201).json({message:'user created successfully'})
    }
    else{
        res.status(400).json({message:'user already exist'})
    }
}catch(e){
    res.status(500).json({message:`server error ${e.message}`})
}
})

//userlogin//

app.post ('/user/login',async(req,res)=>{
    const {user_name,user_password} = req.body 
        const userSignindetailsQuery = `select * from User where user_name=?`
        const userSigninDetails = await db.get(userSignindetailsQuery,[user_name])

        if(!userSigninDetails){
            res.status(400).json({message:"user details not found"})
        }
        else{
            const comparePassword = await bcrypt.compare(user_password,userSigninDetails.user_password)
            if (comparePassword){
                const payload= {user_name:userSigninDetails.user_name}
                const jwt_token = jwt.sign(payload,'secret_token')
                res.status(200).json({message:'login successfull',token:jwt_token})
            }
            else{
                res.status(400).json({message:"password mismatch"})
            }
        }
    })