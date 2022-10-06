//jshint esversion:6
require('dotenv').config();

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");

// const encrypt = require("mongoose-encryption");
// const md5 = require("md5");    // Was used for level 3 authentication.

// const bcrypt = require("bcrypt");  // Was used for level 4 authentication.
// const saltRounds = 12;

const session = require("express-session");   // Used for level 5 authentication.
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const GoogleStrategy = require('passport-google-oauth20').Strategy;    // Uses 3rd party verification through Google.
const findOrCreate = require('mongoose-findOrCreate');

//********** ^  All "require"'s  ^ **********//



const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(express.urlencoded({extended: true}));      // Using express instead of bodyParser

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});

const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

// // This section was used for level 2 authentication, and requires mongoose-encryption from the top.
// // Encrypts ONLY the password of the user, using the key that is stored in the .env file, when newUser is "saved" later.
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// More comple serialization and deserialization, to work with different methods.
passport.serializeUser(function(user, done){
  done(null, user.id);
});
passport.deserializeUser(function(id, done){
  User.findById(id, function(err, user) {
    done(err, user);
  });
});



// Uses the 3rd party authentication through Google. (Order in code is important!)
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,    // In the env file.
    clientSecret: process.env.CLIENT_SECRET,      // In the env file.
    callbackURL: "http://localhost:3000/auth/google/secrets",  // This is the "authorized redirect URI" that we set in the Google API Client ID settings.
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"     // This is an update to get around Google+ being deprecated.
  },
  function(accessToken, refreshToken, profile, cb) {     // Google sends back the accessToken and profile.
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));



//****************** app.get ******************//

app.get("/", function(req, res){
  res.render("home");
});

app.get('/auth/google',
  // This is where we initiate authentication with Google.
  passport.authenticate('google', { scope: ['profile'] })
);

// After the section above, Google will make this get request.
app.get('/auth/google/secrets',
  // This is where we authenticate them locally, and save their login session.
  passport.authenticate('google', { failureRedirect: '/login' }),    // If Google authentication fails, redirects to login page.
  function(req, res) {
    // After successful authentication, redirect to secrets page.
    res.redirect('/secrets');
  });


app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});


app.get("/secrets", function(req, res){
  User.find({"secret": {$ne:null}}, function(err, foundUsers){    // Finds all users who have submitted secrets.
    if (err) {
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  });
});

app.get("/submit", function(req, res){
  if (req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }

})

// Logs the user out when they click the logout button.
app.get("/logout", function(req, res){
  req.logout((err)=>{
    if (err) {
      console.log(err);
    } else {
      res.redirect("/");
    }
  });
});



//****************** app.post ******************//

app.post("/register", function(req, res){
  User.register({username: req.body.username}, req.body.password, function(err, user){
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});


app.post("/login", function(req, res){
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
  req.login(user, function(err){
    if (err) {
      console.log(err);
    } else {
      // Uses passport to login this user and authenticate them, if there are no errors. (login function is from passport)
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});


app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;
  console.log(req.user.id);

  User.findById(req.user.id, function(err, foundUser){
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});


app.listen(3000, function() {
  console.log("Server started on port 3000.");
});
