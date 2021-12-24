var express = require('express');

const functions = require('firebase-functions');

var admin = require("firebase-admin");

var serviceAccount = require("./serviceaccount.json");

var http = require('http');


const cookieParser = require("cookie-parser");
const csrf = require("csurf");
const bodyParser = require("body-parser");

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: "https://synblend.firebaseio.com"
});

const csrfMiddleware = csrf({ cookie: true });

var app = express();

app.use(bodyParser.json());
app.use(cookieParser());
app.use(csrfMiddleware);

app.all("*", (req, res, next) => {
    res.cookie("XSRF-TOKEN", req.csrfToken());
    next();
});

app.set('view engine', 'html');

app.set('views', __dirname + '/views');

app.get('/', function (req, res) { 
    app.use(express.static(__dirname + '/views'));
    const sessionCookie = req.cookies._snbslg || "";

    admin
        .auth()
        .verifySessionCookie(sessionCookie, true /** checkRevoked */)
        .then(() => {
            res.sendFile('index.html', { root: __dirname + '/views' });
        })
        .catch((error) => {
            if (error.code == 'auth/id-token-revoked') {
                res.sendFile('invalid.html', { root: __dirname + '/views' });

            } else {
                res.sendFile('access.html', { root: __dirname + '/views' });
            }
        });
});

app.get("/login", function (req, res) {
    app.use(express.static(__dirname + '/views'));
    const sessionCookie = req.cookies._snbslg || "";

    admin
        .auth()
        .verifySessionCookie(sessionCookie, true /** checkRevoked */)
        .then(() => {
            res.sendFile('index.html', { root: __dirname + '/views' });
        })
        .catch((error) => {
            res.sendFile('login.html', { root: __dirname + '/views' });
        });
});

app.post("/loginsession", (req, res) => {
    const idToken = req.body.idToken.toString();

    const expiresIn = 60 * 60 * 24 * 5 * 1000;
    console.log(idToken);
    admin
        .auth()
        .createSessionCookie(idToken, { expiresIn })
        .then(
            (sessionCookie) => {
                const options = { maxAge: expiresIn, httpOnly: true };
                res.cookie("_snbslg", sessionCookie, options);
                res.end(JSON.stringify({ status: "success" }));
                console.log('Done');
            },
            (error) => {
                res.status(401).send("UNAUTHORIZED REQUEST!");
            }
        );
});

app.get("/signup", function (req, res) {
    app.use(express.static(__dirname + '/views'));
    const sessionCookie = req.cookies._snbslg || "";

    admin
        .auth()
        .verifySessionCookie(sessionCookie, true /** checkRevoked */)
        .then(() => {
            res.sendFile('index.html', { root: __dirname + '/views' });
        })
        .catch((error) => {
            res.sendFile('signup.html', { root: __dirname + '/views' });
        });
});

app.get("/logout", function (req, res) {
    res.clearCookie("_snbslg");
        res.redirect("/login");
});

var port = process.env.PORT || 5000;

app.listen(port, function () {
    console.log('App running on port: ' + port);
});

exports.app = functions.https.onRequest(app);