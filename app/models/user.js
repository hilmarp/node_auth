// Hlutir sem þarf
var mongoose = require('mongoose');
var bcrypt = require('bcrypt-nodejs');

// User schema
var userSchema = mongoose.Schema({

	local :{
		email: String,
		password: String
	},

	facebook :{
		id: String,
		token: String,
		email: String,
		name: String
	},

	twitter: {
		id: String,
		token: String,
		displayName: String,
		username: String
	},

	google: {
		id: String,
		token: String,
		email: String,
		name: String
	}

});

// Methods
// bcrypt
userSchema.methods.generateHash = function(password) {
	return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
};

// Gá hvort password sé valid
userSchema.methods.validPassword = function(password) {
	return bcrypt.compareSync(password, this.local.password);
};

// Búa til user model og birta
module.exports = mongoose.model('User', userSchema);