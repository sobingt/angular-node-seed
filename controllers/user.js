var authController = require('../controllers/auth');
var User = require('../models/User');
/*
 |-----------------------------------------------------------
 | GET /api/me
 |-----------------------------------------------------------
 */
exports.getCurrentUser = function(req, res) {
  User.findById(req.user, function(err, user) {
    res.send(user);
  });
};

/*
 |-----------------------------------------------------------
 | PUT /api/me
 |-----------------------------------------------------------
 */
exports.putCurrentUser = function(req, res) {
  User.findById(req.user, function(err, user) {
    if (!user) {
      return res.status(400).send({ message: 'User not found' });
    }
    user.profile.name = req.body.name || user.profile.name;
    user.email = req.body.email || user.email;
    user.save(function(err) {
      res.status(200).end();
    });
  });
};

