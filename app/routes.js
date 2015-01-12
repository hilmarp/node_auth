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

	// Twitter
	// ===================================================

	// Senda yfir á twitter til að authenticate
	app.get('/auth/twitter', passport.authenticate('twitter'));

	// Twitter sendir notanda til baka hingað með token og profile
	app.get('/auth/twitter/callback', passport.authenticate('twitter', {
		successRedirect: '/profile',
		failureRedirect: '/'
	}));

	// Google
	// ===================================================

	// Senda user yfir á google til að auðkenna sig
	// Scope til að fá profile og email
	app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

	// Google sendir user svo til baka hingað
	app.get('/auth/google/callback', passport.authenticate('google', {
		successRedirect: '/profile',
		failureRedirect: '/'
	}));

	// Logout
	// ===================================================

	app.get('/logout', function(req, res) {
		req.logout();
		res.redirect('/');
	});

	// Authorize (ef user er skráður inn, vill tengja anna social account)
	// ===================================================

	// Local
	app.get('/connect/local', function(req, res) {
		res.render('connect-local', { message: req.flash('loginMessage') });
	});

	app.post('/connect/local', passport.authenticate('local-signup', {
		successRedirect: '/profile',
		failureRedirect: '/connect/local',
		failureFlash: true
	}));

	// Facebook
	// Senda á FB til að gera authentication
	app.get('/connect/facebook', passport.authorize('facebook', { scope: 'email' }));

	// FB callback
	app.get('/connect/facebook/callback', passport.authorize('facebook', {
		successRedirect: '/profile',
		failureRedirect: '/'
	}));

	// Twitter
	app.get('/connect/twitter', passport.authorize('twitter', { scope: 'email' }));

	app.get('/connect/twitter/callback', passport.authorize('twitter', {
		successRedirect: '/profile',
		failureRedirect: '/'
	}));

	// Google
	app.get('/connect/google', passport.authorize('google', { scope: ['profile', 'email'] }));

	app.get('/connect/google', passport.authorize('google', {
		successRedirect: '/profile',
		failureRedirect: '/'
	}));

	// Unlinking
	// ===================================================
	// Henda út token, nema í local þá email og pass

	// Local
	app.get('/unlink/local', function(req, res) {
		var user = req.user;
		user.local.email = undefined;
		user.local.password = undefined;
		user.save(function(err) {
			res.redirect('/profile');
		});
	});

	// Facebook
	app.get('/unlink/facebook', function(req, res) {
		var user = req.user;
		user.facebook.token = undefined;
		user.save(function(err) {
			res.redirect('/profile');
		});
	});

	// Twitter
	app.get('/unlink/twitter', function(req, res) {
		var user = req.user;
		user.twitter.token = undefined;
		user.save(function(err) {
			res.redirect('/profile');
		});
	});

	// Google
	app.get('/unlink/googlek', function(req, res) {
		var user = req.user;
		user.google.token = undefined;
		user.save(function(err) {
			res.redirect('/profile');
		});
	});

	// Middleware sem athugar hvort notandi sé skráður inn
	// ===================================================
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