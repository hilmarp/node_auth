// Það sem þarf að nota
var LocalStrategy = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var TwitterStrategy = require('passport-twitter').Strategy;
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;

// Ná í User model
var User = require('../app/models/user');

// Ná í social stillingar
var configAuth = require('./auth');

// Leyfa appinu að nota function
module.exports = function(passport) {

	// Passport setup
	// ===================================================

	// Serialize user fyrir session
	passport.serializeUser(function(user, done) {
		done(null, user.id);
	});

	// Deserialize user
	passport.deserializeUser(function(id, done) {
		User.findById(id, function(err, user) {
			done(err, user);
		});
	});

	// Local signup
	// ===================================================

	// Setjum nafn á strategy, annars væri það default local
	passport.use('local-signup', new LocalStrategy({
		// Notar default bara username og password, breytum í email og password
		usernameField: 'email',
		passwordField: 'password',
		passReqToCallback: true // Henda allri req í callback
	},
	// Callback með email og password frá form
	function(req, email, password, done) {
		// Async
		// User.findOne keyrir ekki nema gögn séu send til baka
		process.nextTick(function() {
			// Finna user með sama email og kom úr forminu
			// Gá hvort user sé þegar til
			User.findOne({ 'local.email': email }, function(err, user) {
				if (err) {
					return done(err);
				}

				// Gá hvort það sé user með þetta email
				if (user) {
					return done(null, false, req.flash('signupMessage', 'Netfang er þegar skráð'));
				} else {
					// Ef það er enginn notandi með þetta email
					// Búa til user
					var newUser = new User();

					// Setja local creds
					newUser.local.email = email;
					newUser.local.password = newUser.generateHash(password);

					// Save
					newUser.save(function(err) {
						if (err) {
							throw err;
						}

						return done(null, newUser);
					});
				}
			});
		});
	}));

	// Local login
	// ===================================================

	passport.use('local-login', new LocalStrategy({
		// Override username með email
		usernameField: 'email',
		passwordField: 'password',
		passReqToCallback: true
	},
	// Callback með email og password frá form
	function(req, email, password, done) {
		// Tjékka email, hvort það sé til, þ.e. hvort notandi sé skráður
		User.findOne({ 'local.email': email }, function(err, user) {
			if (err) {
				return done(err);
			}

			// Ef enginn user fannst
			if (!user) {
				return done(null, false, req.flash('loginMessage', 'Notandi fannst ekki'));
			}

			// Ef notandi fannst en password er rangt
			if (!user.validPassword(password)) {
				return done(null, false, req.flash('loginMessage', 'Rangt lykilorð'));
			}

			// Allt gékk upp
			return done(null, user);
		});
	}));

	// Facebook signup
	// ===================================================

	passport.use(new FacebookStrategy({
		// Ná í app id og secret
		clientID: configAuth.facebookAuth.clientID,
		clientSecret: configAuth.facebookAuth.clientSecret,
		callbackURL: configAuth.facebookAuth.callbackURL
	},
	// Facebook sendir til baka token og profile
	function(req, token, refreshToken, profile, done) {
		// Async
		process.nextTick(function() {
			// Gá hvort user er skráður inn
			if (!req.user) {
				// Finna user í DB útfrá facebook id
				User.findOne({ 'facebook.id': profile.id }, function(err, user) {
					// Ef ekki tókst að tengjast db
					if (err) {
						return done(err);
					}

					// Ef user fannst, login
					if (user) {
						// Ef það er user með id en ekki token þá hefur hann unlinkað sig
						// Bæta við token og info
						if (!user.facebook.token) {
							user.facebook.token = token;
							user.facebook.name = profile.name.givenName + ' ' + profile.name.familyName;
							user.facebook.email = profile.emails[0].value;
							user.save(function(err) {
								if (err) {
									throw err;
								}

								return done(null, user);
							});
						}

						return done(null, user);
					} else {
						// Ef user með fb id fannst ekki, búa hann til
						var newUser = new User();

						// Vista fb info
						newUser.facebook.id = profile.id;
						newUser.facebook.token = token;
						newUser.facebook.name = profile.name.givenName + ' ' + profile.name.familyName;
						// FB getur skilað nokkrum email, tökum fyrsta
						newUser.facebook.email = profile.emails[0].value;

						// Vista user
						newUser.save(function(err) {
							if (err) {
								throw err;
							}

							// Returna nýja user
							return done(null, newUser);
						});
					}
				});
			} else {
				// Notandi er skráður inn
				// Þarf að linka account
				var user = req.user;

				user.facebook.id = profile.id;
				user.facebook.token = token;
				user.facebook.name = profile.name.givenName + ' ' + profile.name.familyName;
				user.facebook.email = profile.emails[0].value;

				// Vista
				user.save(function(err) {
					if (err) {
						throw err;
					}

					return done(null, user);
				});
			}
		});
	}));

	// Twitter signup
	// ===================================================

	passport.use(new TwitterStrategy({
		// Keys
		consumerKey: configAuth.twitterAuth.consumerKey,
		consumerSecret: configAuth.twitterAuth.consumerSecret,
		callbackURL: configAuth.twitterAuth.callbackURL
	},
	function(token, tokenSecret, profile, done) {
		// Async
		// FindOne keyrir þegar öll gögn eru komin til baka frá twitter
		process.nextTick(function() {
			User.findOne({ 'twitter.id': profile.id }, function(err, user) {
				// Ef error að tengjast db
				if (err) {
					return done(err);
				}

				// Ef user með id finnst, login
				if (user) {
					return done(null, user);
				} else {
					// Ef user með id finnst ekki, create
					var newUser = new User();

					// Info til að vista
					newUser.twitter.id = profile.id;
					newUser.twitter.token = token;
					newUser.twitter.username = profile.username;
					newUser.twitter.displayName = profile.displayName;

					// Save
					newUser.save(function(err) {
						if (err) {
							throw err;
						}

						return done(null, newUser);
					});
				}
			});
		});
	}));

	// Google signup
	// ===================================================

	passport.use(new GoogleStrategy({
		// Keys
		clientID: configAuth.googleAuth.clientID,
		clientSecret: configAuth.googleAuth.clientSecret,
		callbackURL: configAuth.googleAuth.callbackURL
	},
	function(token, refreshToken, profile, done) {
		// Async
		// Þegar gögn eru komin frá Google þá keyrir findOne
		process.nextTick(function() {
			User.findOne({ 'google.id': profile.id }, function(err, user) {
				if (err) {
					return done(err);
				}

				if (user) {
					// Ef user er þegar skráður
					return done(null, user);
				} else {
					// Nýskráning
					var newUser = new User();

					// Vista gögn
					newUser.google.id = profile.id;
					newUser.google.token = token;
					newUser.google.name = profile.displayName;
					newUser.google.email = profile.emails[0].value;

					// Vista
					newUser.save(function(err) {
						if (err) {
							throw err;
						}

						return done(null, newUser);
					});
				}
			});
		});
	}));

};