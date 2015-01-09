// Það sem þarf að nota
var LocalStrategy = require('passport-local').Strategy;

// Ná í User model
var User = require('../app/models/user');

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

};