const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const Schema = mongoose.Schema;

const SALT_ROUNDS = 11;

const UserSchema = new mongoose.Schema({
  // create your user schema here.
  // username: required, unique and lowercase
  // password: required
  username: {
    type: String,
    require: true,
    unique: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true
  }
});

UserSchema.pre('save', function(next) {
  // https://github.com/kelektiv/node.bcrypt.js#usage
  // Fill this middleware in with the Proper password encrypting,
  bcrypt
    .hash(this.password, 5)
    .then(hash => {
      this.password = hash;

      next();
    })
    .catch(err => {
      console.log('error', err);
    });
  // if there is an error here you'll need to handle it by calling next(err);
  // Once the password is encrypted, call next() so that your userController and create a user
});

// https://github.com/kelektiv/node.bcrypt.js#usage
// Fill this method in with the Proper password comparing, bcrypt.compare()
// Your controller will be responsible for sending the information here for password comparison
// Once you have the user, you'll need to pass the encrypted pw and the plaintext pw to the compare function
UserSchema.methods.checkPassword = function(plainTextPW, callBack) {
  bcrypt.compare(plainTextPW, this.password, (err, isValid) => {
    if (err) {
      return callBack(err);
    }
    callBack(null, isValid);
  });
};

module.exports = mongoose.model('User', UserSchema);
