const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');

function initialize(passport, getUserByEmail, getUserById) {
  // we call this from our login using our email and password, to make sure the user is correct
  const authenticateUser = async (email, password, done) => {
    const user = getUserByEmail(email);
    // check if there is a user with the email he entered
    if (user == null) {
      return done(null, false, { message: 'No user with that email' });
    }

    // if user is found, check that the email and passwords are authenticated
    try {
      if (await bcrypt.compare(password, user.password)) {
        // user is authenticated
        done(null, user);
      } else {
        // user password did not match
        return done(null, false, { message: 'Password incorrect' });
      }
    } catch (e) {
      return done(e);
    }
  };

  passport.use(new LocalStrategy({ usernameField: 'email' }, authenticateUser));
  passport.serializeUser((user, done) => {
    done(null, user.id);
  });
  passport.deserializeUser((id, done) => {
    return done(null, getUserById(id));
  });
}

module.exports = initialize;
