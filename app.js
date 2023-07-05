// require dotenv and configure it to access env variables
require("dotenv").config();

// Passport Package/Express-Sessions/PassportLocalMongoose
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
// OAuth
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook");

// Initializing Express, EJS and Mongoose.
const express = require("express");
const ejs = require("ejs");
const app = express();
const mongoose = require("mongoose");
const findOrCreate = require("mongoose-findorcreate");

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));

// Initialises Express-session
app.use(
  session({
    secret: "This is our secret.",
    resave: false, //don't save session if unmodified
    saveUninitialized: true, //store session everytime for request
    cookie: { secure: false }, //allow cookies to be sent over HTTP connection for local development
  })
);

// Initialises Passport.js
app.use(passport.initialize());
app.use(passport.session());

main().catch((err) => console.log(err));

async function main() {
  await mongoose.connect("mongodb://127.0.0.1:27017/userDB");

  const usersSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: String,
  });

  // PassportlocalMongoose plugin-- Hash and salt passwords and save our users to DB
  usersSchema.plugin(passportLocalMongoose);
  //   Mongoose-findOrCreate pluin
  usersSchema.plugin(findOrCreate);

  const User = mongoose.model("User", usersSchema);

  //  Initializing strategy for OAuth.
  passport.use(User.createStrategy());

  passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
      return cb(null, {
        id: user._id,
        username: user.username,
      });
    });
  });

  passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
      return cb(null, user);
    });
  });

  //   OAuth with Facebook and Google
  passport.use(
    new FacebookStrategy(
      {
        clientID: process.env.FACEBOOK_APP_ID,
        clientSecret: process.env.FACEBOOK_APP_SECRET,
        callbackURL: "http://localhost:3000/auth/facebook/secrets",
        state: true,
      },
      function verify(accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ facebookId: profile.id }, function (err, user) {
          return cb(err, user); // Passport verify function must call cb to complete authentication
        });
      }
    )
  );

  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets",
        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
      },
      function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
          return cb(err, user);
        });
      }
    )
  );

  //   APPS MAIN ROUTES
  app.get("/", (req, res) => {
    res.render("home");
  });

  //   Use Passport's Google strategy to authenticate users.
  app.get(
    "/auth/google",
    passport.authenticate("google", { scope: "profile" })
  );
  //   Redirect user back to our app once they logged in google.
  //   Use the options(successRedirect and failureRedirect) in Passport's authenticate function to specify routes.
  app.get(
    "/auth/google/secrets",
    passport.authenticate("google", {
      successRedirect: "/secrets",
      failureRedirect: "/login",
    })
  );

  // Use Passport's Facebook strategy to authenticate users.
  app.get("/auth/facebook", passport.authenticate("facebook"));
  app.get(
    "/auth/facebook/secrets",
    passport.authenticate("facebook", {
      successRedirect: "/secrets",
      failureRedirect: "/login",
    })
  );

  app.get("/login", (req, res) => {
    res.render("login", { errMsg: "" });
  });
  app.get("/register", (req, res) => {
    res.render("register");
  });

  //   Render all the secrets submitted by all users without showing any users' information.
  app.get("/secrets", (req, res) => {
    User.find({ secret: { $ne: null } })
      .then((foundUsers) => {
        res.render("secrets", { usersWithSecrets: foundUsers });
      })
      .catch((err) => {
        console.log(err);
      });
  });

  //   Render "submit" page once user is logged-in or registered, otherwise rediret user to the "login" page.
  app.get("/submit", (req, res) => {
    if (req.isAuthenticated()) {
      res.render("submit");
    } else {
      res.redirect("/login");
    }
  });

  //   LOGOUT ROUTE
  //   Log out users once they click logout button, end their session and redirect to home page.
  app.get("/logout", (req, res, next) => {
    req.logout(function (err) {
      if (err) {
        return next(err);
      } else {
        res.redirect("/");
      }
    });
  });

  //   POST ROUTE
  //   Register a new user using passportLocalMongoose package.
  app.post("/register", async (req, res) => {
    try {
      const user = new User({ username: req.body.username });
      await User.register(user, req.body.password);
      passport.authenticate("local")(req, res, () => {
        res.redirect("/secrets");
      });
    } catch (err) {
      console.log(err);
      res.redirect("/register");
    }
  });

  // Authenticate users using Passport, to access "/secrets" page after logged in.
  app.post("/login", (req, res, next) => {
    const user = new User({
      username: req.body.username,
      password: req.body.password,
    });

    // Notify users if their username or password is incorrect.
    req.login(user, function (err) {
      if (err) {
        res.render("/login", {
          errMsg: "An error occurred. Please try again.",
        });
        console.log(err);
      } else {
        passport.authenticate("local", (err, user) => {
          if (err || !user) {
            res.render("login", {
              errMsg: "Invalid username or password.",
            });
          } else {
            res.redirect("/secrets");
          }
        })(req, res, next);
      }
    });
  });

  // Parse and save the secret that user entered on the "submit" page along with the user's info
  app.post("/submit", (req, res) => {
    const submittedSecret = req.body.secret;
    User.findById(req.user.id)
      .then((foundUser) => {
        foundUser.secret = submittedSecret;
        foundUser.save().then(res.redirect("/secrets"));
      })
      .catch((err) => console.log(err));
  });

  app.listen(3000, () => {
    console.log("Server started on port 3000");
  });
}
