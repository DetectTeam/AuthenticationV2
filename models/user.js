var mongoose = require('mongoose');
var bcrypt = require('bcryptjs'); //Hash Passwords

// User Schema
var UserSchema = mongoose.Schema({

  username: {
		type: String,
		index:true
	},
  uid: {
    type: String,
  },
	password: {
		type: String
	},
	email: {
		type: String,
		max: 100
	},
	encryptedEmail:
	{
		type: String
	},
	name: {
		type: String
	}
});

var User = module.exports = mongoose.model('Users', UserSchema);

//Create new user
module.exports.createUser = function(newUser, callback)
{

    bcrypt.genSalt(10, function(err, salt)
    {
        bcrypt.hash(newUser.password, salt, function(err, hash)
        {
            newUser.password = hash;
            console.log( newUser.password );
            bcrypt.genSalt(10, function(err, salt)
            {
                bcrypt.hash(newUser.email, salt, function(err, hash)
                {
                    newUser.email = hash;
                    newUser.save(callback);

                });
            });
        });

    });

}

module.exports.comparePassword = function(candidatePassword, hash, callback){
	bcrypt.compare(candidatePassword, hash, function(err, isMatch) {
    	if(err) throw err;
    	callback(null, isMatch);
	});

}

module.exports.getUserByUsername = function(username, callback){
	var query = {username: username};
	User.findOne(query, callback);
}

module.exports.getUserById = function(id, callback){
	User.findById(id, callback);
}


module.exports.findEmail = function( emailToFind , callback ){
	//User.find().forEach( function(myDoc) { console.log( "User: " + myDoc.name ); } );

	User.findOne().then((recs) => {

    	if( recs.length == 0 )
    	{
    		callback( null, false );
    	}
    	else
      {
    		recs.forEach((rec) => {

    			console.log( '>>>> ' + rec.email + ' ' + emailToFind );
    			bcrypt.compare(emailToFind, rec.email, function(err, isMatch)
    			{

    				//	console.log( 'is match: ' + isMatch );
            if(err) throw err;
        //console.log( err );
      //	console.log( 'is match: ' + isMatch );
        callback(null, isMatch);


    			});

    		});
    	}
    });

}
