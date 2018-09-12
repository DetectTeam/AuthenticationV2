var mongo = require('mongodb');
var mongoose = require('mongoose');

connectDB = function()
{
  console.log('connection to db....');
  //mongoose.connect('mongodb://localhost/loginApp', { useNewUrlParser: true } );
  mongoose.connect('mongodb://wormy:test123@ds247430.mlab.com:47430/detect_user_data', { useNewUrlParser: true });
  //mongoose.connect('mongodb://eoghan:midkemia76@ds161751.mlab.com:61751/detect', { useNewUrlParser: false });
  const db = mongoose.connection;
  db.on('error', console.error.bind(console, 'connection error ::::'));
  db.once('open', function()
  {
    // we're connected!
    console.log('Connected to DB...');
  });

}

module.exports = connectDB;
