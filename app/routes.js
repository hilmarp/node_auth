module.exports = function(app, passport) {

	// Home
	// ===================================================

	app.get('/', function(req, res) {
		res.render('index');
	});

	// Login
	// ===================================================

	// Sýna login formið og flash data
	app.get('/login', function(req, res) {
		res.render('login', { message: req.flash('loginMessage') });
	});

	// Login post
	app.post('/login', passport.authenticate('local-login', {
		successRedirect: '/profile',
		failureRedirect: '/login',
		failureFlash: true // Leyfa flash
	}));

	// Signup
	// ===================================================

	// Sýna signup formið
	app.get('/signup', function(req, res) {
		res.render('signup', { message: req.flash('signupMessage') });
	});

	// Signup post
	app.post('/signup', passport.authenticate('local-signup', {
		successRedirect: '/profile',
		failureRedirect: '/signup',
		failureFlash: true // Leyfa flash
	}));

	// Profile
	// ===================================================

	// Verður að vera loggaður inn til að skoða
	// Notum middleware til þess að athuga það
	app.get('/profile', isLoggedIn, function(req, res) {
		res.render('profile', {
			user: req.user // Ná í user úr session og senda í template
		});
	});

	// Facebook
	// ===================================================

	// FB auth og login
	app.get('/auth/facebook', passport.authenticate('facebook', { scope: 'email' }));

	// Callback eftir að fb hefur authenticatað
	app.get('/auth/facebook/callback', passport.authenticate('facebook', {
		successRedirect: '/profile',
		failureRedirect: '/'
	}));

	// Logout
	// ===================================================

	app.get('/logout', function(req, res) {
		req.logout();
		res.redirect('/');
	});

	// Middleware sem athugar hvort notandi sé skráður inn
	function isLoggedIn(req, res, next) {
		// Ef user er skráður inn í session þá halda áfram
		if (req.isAuthenticated()) {
			return next();
		} else {
			// Annars henda þeim á forsíðu
			res.redirect('/');
		}
	};

};