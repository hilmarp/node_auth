// Setup
// ===================================================

// Allt sem þarf að nota
var express = require('express');
var app = express();
var port = process.env.PORT || 3000;
var mongoose = require('mongoose');
var passport = require('passport');
var flash = require('connect-flash');
var morgan = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var session = require('express-session');
var configDB = require('./config/database.js');

// Stillingar
// ===================================================

// Tengjast db
mongoose.connect(configDB.url);

// Passport stillingar
require('./config/passport')(passport);

// Express stillingar
app.use(express.static(__dirname + '/public'));
app.use(morgan('dev')); // Logga öllu í console
app.use(cookieParser()); // Lesa cookies
app.use(bodyParser.urlencoded({ extended: true })); // Fá info frá post

// Nota ejs
app.set('view engine', 'ejs');

// Passport stillingar
app.use(session({ secret: 'hilmarerbestur' }));
app.use(passport.initialize());
app.use(passport.session()); // Login í session
app.use(flash()); // Flash skilaboð geymd í session

// Routes
// ===================================================

// Hlaða inn routes og gefa þeim app og passport
require('./app/routes.js')(app, passport);

// Keyra app
// ===================================================
app.listen(port);
console.log('Server i gangi a porti ' + port);