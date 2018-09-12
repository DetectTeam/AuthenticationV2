var express = require('express');
var router = express.Router();

const jwt = require('jsonwebtoken');

//Get Homepage
router.get( '/', function( req, res )
{

    res.send('Welcome');

});

module.exports = router;
