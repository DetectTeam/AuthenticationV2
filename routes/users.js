var express = require('express');
var router = express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var jwt = require('jsonwebtoken');
var User = require('../models/user');
var uuidv1 = require('uuid/v1');

var uid = '';

// Passport init
router.use(passport.initialize());
router.use(passport.session());


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

                    message = {'message':'user-exists'};
                    res.status(409).send( message );
                  }
          });

    }
    else
    {
        message = errors;
        res.status(422).send( message );
    }

});

passport.use('local', new LocalStrategy(
	function (username, password, done)
  {

    if( username.length === '' )
    {
      console.log( "username not defined.." );
    }

		User.getUserByUsername(username, function (err, user) {
			if (err) throw err;
			if (!user) {
				return done(null, false, { message: 'Unknown User' });
			}

			User.comparePassword(password, user.password, function (err, isMatch) {
				if (err) throw err;
				if (isMatch) {
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


  router.post('/login', (req, res) => {
    passport.authenticate('local', function (err, user, info) {
        if (err) {
            return res.status(401).json(err);
        }
        if (user) {
          //  const token = user.generateJwt();
            return res.status(200).json({
                "token": "yay im a token...."
            });
        } else {
            res.status(401).json(info);
        }
    })(req, res)
})


  // router.post( '/login', Auth );
  //
  //
  //   function Auth( req, res, next)
  //   {
  //       passport.authenticate('local',
  //       {
  //         successRedirect: '/',
  //         failureRedirect: '/users/login'
  //       } ,function(err, user, info)
  //       {
  //         console.log( 'I got called' );
  //       res.send('This Works ok......');
  //     })(req,res,next);
  //
  //   }






  router.get('/logout', function (req, res)
  {
	req.logout();

	req.flash('success_msg', 'You are logged out');

	res.redirect('/users/login');
});


module.exports = router;
