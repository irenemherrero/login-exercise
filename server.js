const path = require('path')
const express = require('express')
const https = require('https')
const fs = require('fs')
const helmet = require('helmet')
const passport = require('passport')
// const cookieSession = require('cookie-session')
const { Strategy } = require('passport-google-oauth2')

require('dotenv').config()

const PORT = 3000

const config = {
	CLIENT_ID: process.env.CLIENT_ID,
	CLIENT_SECRET: process.env.CLIENT_SECRET,
	COOKIE_KEY_1: process.env.COOKIE_KEY_1,
	COOKIE_KEY_2: process.env.COOKIE_KEY_2
}

const AUTH_OPTIONS = {
	callbackURL: '/auth/google/callback',
	clientID: config.CLIENT_ID,
	clientSecret: config.CLIENT_SECRET
}

const verifyCallback = (accessToken, refreshToken, profile, done) => {
	console.log('accessToken', accessToken)
	done(null, profile)
}

passport.use(new Strategy(AUTH_OPTIONS, verifyCallback))

// Save session to the cookie (encriptar)
// passport.serializeUser((user, done) => {
// 	done(null, user)
// })

// Read session from cookie (desencriptar)
// passport.deserializeUser((obj, done) => {
// 	done(null, obj)
// })

const app = express()

app.use(helmet()) // se pone encima de todos los endpoints para asegurarlos

// app.use(cookieSession({
// 	name: 'session',
// 	maxAge: 24 * 60 * 60 * 1000,
// 	keys: [config.COOKIE_KEY_1, config.COOKIE_KEY_2]
// }))

app.use(passport.initialize())
// app.use(passport.session())

const checkLoggedIn = (req, res, next) => {
	const isLoggedIn = true
	if (!isLoggedIn) {
		return res.status(401).json({
			error: 'You must log in!'
		})
	}
	next()
}

// 1. endpoint para redirigir a la página de login de google
app.get('/auth/google', 
	passport.authenticate('google', {
		scope: ['email']
	})
)

// 2. endpoint al que se va a devolver la respuesta de google cuando termine el proceso de auth
app.get('/auth/google/callback', 
	passport.authenticate('google', {
		failureRedirect: '/failure',
		successRedirect: '/',
	}, 
	(req, res) => {
		console.log('Google called us back!')
	})
)

// endpoint de logout
app.get('/auth/logout', (req, res) => {
	req.logout()
})

app.get('/secret', checkLoggedIn, (req, res) => {
	res.send('This is your personal secret value: 23')
})

app.get('/failure', (req, res) => {
	res.send('Failed sign in')
})

app.get('/', (req, res) => {
	res.sendFile(path.join(__dirname, 'public', 'index.html'))
})

// versión no segura sin https
// app.listen(PORT, () => {
// 	console.log(`Listening on port ${PORT}`)
// })

https.createServer({
	key: fs.readFileSync('key.pem'),
	cert: fs.readFileSync('cert.pem')
}, app).listen(PORT, () => {
	console.log(`Listening on port ${PORT}`)
})