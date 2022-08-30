require('dotenv').config()

const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')

app.set('view-engine', 'ejs')
app.use(express.urlencoded({ extended: false }))
app.use(express.json())
app.use(cookieParser())

const users = []

app.get('/register', (req, res) => {
    res.render('register.ejs')
})

app.get('/login', (req, res) => {
    res.render('login.ejs')
})

app.get('/protected', authorization, (req, res) => {
    res.json({ message: "you are an authorized user!" })
})

app.post('/register', async (req, res) => {
    try {
        const salt = await bcrypt.genSalt()
        const hashedPassword = await bcrypt.hash(req.body.password, salt)
        const user = { username: req.body.username, password: hashedPassword }
        users.push(user)
        res.redirect('/login')
    }
    catch (err){
        res.redirect('/register')
        res.status(500).send()
    }
})

app.post('/login', async (req, res) => {
    const user = users.find(user => user.username === req.body.username)
    if (user === null) {
        return res.status(400).send('cannot find user')
    }
    try {
        if (await bcrypt.compare(req.body.password, user.password)) {
            const username = req.body.username
            const user = { name: username }

            const accessToken = generateAccessToken(user)

            res.cookie("access_token", accessToken, {
                httpOnly: true,
            })

            res.redirect('/protected')
        }
        else {
            res.send('not allowed')
        }
    }
    catch {
        res.status(500).send()
    }
})

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET)
}

function authorization(req, res, next) {
    const token = req.cookies.access_token 
    if (!token) {
        return res.sendStatus(403)
    }
    try {
        const data = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
        return next()
    }
    catch {
        return res.sendStatus(403)
    }
}

app.listen(3000)