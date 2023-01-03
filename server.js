const path = require('path')
const express = require('express')
const https = require('https')
const fs = require('fs')

const helmet = require('helmet')
const passport = require('passport')
const cookieSession = require('cookie-session')
const GoogleStrategy = require('passport-google-oauth20').Strategy;

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
	done(null, profile)
}

passport.use(new GoogleStrategy(AUTH_OPTIONS, verifyCallback))

// 3. middleware that encripts the cookie after successful login following cookieSession config (below, line 56)
// sends the resulting encripted cookie to the browser -> cookie contains encripted user data
// saves the cookie in passport to check if the user exists when it receives a cookie from the browser
passport.serializeUser((user, done) => {
	done(null, user.id)
})

// 4. middleware that translates the cookie received from the browser to get the user data,
// Checkes that the session for this user exists (from saved ones in passport)
// Could also add some data from user already available in a database, see commented code below.
// If session is ok, req param in following routes will have req.user set, with user data.
passport.deserializeUser((id, done) => {
	// User.findById(id).then(user => {
	// 	done(null, user)
	// })
	done(null, id)
})

const app = express()

app.use(helmet()) // it is set on top of all middlewares below to secure them

app.use(cookieSession({
	name: 'session',
	maxAge: 24 * 60 * 60 * 1000,
	keys: [config.COOKIE_KEY_1, config.COOKIE_KEY_2]
	// keys: sirve para firmar la cookie, otra capa de seguridad. 
	// Cuando nos venga una cookie del browser, sabremos si es nuestra porque se ha encriptado con esta key
	// esto se hace con las client side sessions, o sea, las que se guardan en las cookies del navegador
}))

app.use(passport.initialize())
app.use(passport.session()) 

const checkLoggedIn = (req, res, next) => {
	const isLoggedIn = req.isAuthenticated() && req.user
	if (!isLoggedIn) {
		return res.status(401).json({
			error: 'You must log in!'
		})
	}
	next()
}

// 1. login endpoint that redirects to google login page
app.get('/auth/google', 
	passport.authenticate('google', {
		scope: ['email']
	})
)

// 2. callback endpoint that receives the response from google after login.
app.get('/auth/google/callback', 
	passport.authenticate('google', { failureRedirect: '/failure', successReturnToOrRedirect: '/successLogin', }))

app.get('/auth/logout', (req, res) => {
	req.logout()
	return res.redirect('/')
})

app.get('/secret', checkLoggedIn, (req, res) => {
	res.send('This is your personal secret value: 23')
})

app.get('/failure', (req, res) => {
	res.send('Failed sign in')
})

app.get('/successLogin', (req, res) => {
	res.send('You logged in successfully')
})

app.get('/', (req, res) => {
	res.sendFile(path.join(__dirname, 'public', 'index.html'))
})

// Non secure alterantive to create the server without https.
// app.listen(PORT, () => {
// 	console.log(`Listening on port ${PORT}`)
// })

https.createServer({
	key: fs.readFileSync('key.pem'),
	cert: fs.readFileSync('cert.pem')
}, app).listen(PORT, () => {
	console.log(`Listening on port ${PORT}`)
})