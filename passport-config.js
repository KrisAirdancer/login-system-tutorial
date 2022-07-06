/* This file contains all of the information for passport as well as a bunch
 * of the setup code for passport.
 */

// A strategy defines the authentication mecnanism/proceedure to be used when authenticating users.
const LocalStrategy = require('passport-local').Strategy
const bcrypt = require('bcrypt')

/* passport is the passport object
 * getUserByEmail is a function that looks a user up using their email
 * getUserById is a fucntion that looks a user up using their id
 */
function initialize(passport, getUserByEmail, getUserById) {

  /* uthenticateUser is the function that we can call to authenticate a user. This
   * method is passed into .get(), .post(), etc. to authenticate users at the time
   * a request is made by that user.
   * The parameters that this method takes in are used as information to
   * authenticate the user. The 'done' parameter is a function that we call when
   * we have finished authenticating the user.
   */
  const authenticateUser = async (email, password, done) => {
    // Get the user object
    const user = getUserByEmail(email)
    /* If we can't find the user, we call done with information about not being
     * able to find the user.
     * 1st parameter: Specifies/returns the error - we don't have an error, so return `null`
     * 2nd parameter: Specifies/returns the user - we didn't find a user, so return `false`, didn't find a user.
     * 3rd parameter: Specifies/returns a message
     */
    if (user == null) {
      return done(null, false, { message: 'No user with that email' })
    }

    /* If we made it this far, we must have found a user (else we would have triggered
     * the above if statement). 
     */
    try {
      // Compare the password entered by the user with the encrypted one on file.
      if (await bcrypt.compare(password, user.password)) {
        // If passwords match, return the user that we want to authenticate as. That is, the user profile that the user logged in as.
        return done(null, user)
      } else {
        /* If passwords don't match, return no user and a message that the passwords didn't match.
         * Note: The message here is the message that is displayed on the GUI by express-flash.
         */
        return done(null, false, { message: 'Password incorrect' })
      }
    } catch (e) {
      // Return the error if one was thrown.
      return done(e)
    }
  }

  /* This creates a new LocalStrategy object and passes it to the pasport object to be used
   * as the authentication strategy for that passport object.
   * Note: The options object passed in defaults to using 'username' as the value
   * for 'usernameField'. Here, we are instructing it to use 'email' instead.
   * Note: The values passed to 'usernameField', etc. must match the 'name' attribute
   * of the form whose data will be used to authenticate the user.
   * Note: authenticateUser is the function that we can call to authenticate a user. This
   * method is passed into .get(), .post(), etc. to authenticate users at the time
   * a request is made by that user.
   */
  passport.use(new LocalStrategy({ usernameField: 'email', passwordField: 'password' }, authenticateUser))
  /* Serialization converts the given data into a byte stream.
     * 1st parameter: Specifies/returns the error - we don't have an error, so return `null`
     * 2nd parameter: Specifies/returns the id (in this case, other information can be passed in here.)
  */
  passport.serializeUser((user, done) => done(null, user.id))
  /* Deserializastion converts a given byte stream back into data.
   * 1st parameter: Specifies/returns the error - we don't have an error, so return `null`
   * 2nd parameter: Specifies/returns the iuser.
   */
  passport.deserializeUser((id, done) => {
    return done(null, getUserById(id))
  })
}

// Exporting the initizalize function so that we can require and thus use it in other modules.
module.exports = initialize