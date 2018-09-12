var express = require('express');
var router = express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var jwt = require('jsonwebtoken');
var User = require('../models/user');
var uuidv1 = require('uuid/v1');

var uid = '';
//Registration End Point
router.post( '/register', function( req, res )
{

  console.log( req.body );

    var name = req.body.name;
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;
    var password2 = req.body.password2

    var message = {};
    var status = 401;

    console.log( name + ' : ' + username + ' : ' + email + ' : ' + password + ' : ' + password2 );

    // Validation
    req.checkBody('name', 'First Name is required').notEmpty();
    req.checkBody('username', 'Username is required').notEmpty();
    req.checkBody('email', 'Email is not valid').isEmail();
    req.checkBody('password', 'Password is required').notEmpty();
    req.checkBody('password2', 'Passwords do not match').equals(req.body.password);

    var errors = req.validationErrors();

    if( !errors )
    {


      //Check if user exists
      User.findOne({username:{
          "$regex": "^" + username + "\\b", "$options": "i"}} , function( err, user ){

                  if( !user ) //user exists
                  {

                    uid = uuidv1();
                    var newUser = new User({
						        name: name,
						        email: email,
                    encryptedEmail: email,
						        username: username,
                    password: password,
                    uid: uid

					});
					User.createUser(newUser, function (err, user) {
						if (err) throw err;
						console.log(user);
					});

                    status = 201;
                    message = {'message':'user-created','uid':uid};
                    res.status(201).send( message );
                  }
                  else {
                    status = 200;
                    message = {'message':'user-exists'};
                    res.status(200).send( message );
                  }
          });

    }
    else
    {
        status = 200;
        message = errors;
        res.status(status).send( message );
    }

});

passport.use(new LocalStrategy(
	function (username, password, done) {
    console.log( 'PASSPORT WORKING' );
		User.getUserByUsername(username, function (err, user) {
			if (err) throw err;
			if (!user) {
        console.log('NOT USER');
				return done(null, false, { message: 'Unknown User' });
			}

			User.comparePassword(password, user.password, function (err, isMatch) {
				if (err) throw err;
				if (isMatch) {
          console.log('password match');
					return done(null, user);
				} else {
          console.log('Invalid password');
					return done(null, false, { message: 'Invalid password' });
				}
			});
		});
	}));

  passport.serializeUser(function (user, done) {
done(null, user.id);
});

passport.deserializeUser(function (id, done) {
	User.getUserById(id, function (err, user) {
		done(err, user);
	});
});

  router.get('/login', function(req, res){
    res.send( 'login get' );
  });

  router.post('/login',
	passport.authenticate('local', { successRedirect: '/', failureRedirect: '/users/login', failureFlash: true }),
	function (req, res) {

    res.send( req.body );

		res.redirect('/');
	});

  router.get('/logout', function (req, res)
  {
	req.logout();

	req.flash('success_msg', 'You are logged out');

	res.redirect('/users/login');
});


module.exports = router;
