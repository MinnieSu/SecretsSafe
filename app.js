// require dotenv and configure it to access env variables
require("dotenv").config();

// Passport Package/Express-Sessions/PassportLocalMongoose
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
// OAuth
const GoogleStrategy = require("passport-google-oauth20").Strategy;

// Initializing Express, EJS and Mongoose.
const express = require("express");
const ejs = require("ejs");
const app = express();
const mongoose = require("mongoose");

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));

// Initialises Express-session
app.use(
  session({
    secret: "This is our secret.",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }, // Remember to set this
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
    secret: String,
  });

  // PassportlocalMongoose plugin-- Hash and salt passwords and save our users to DB
  usersSchema.plugin(passportLocalMongoose);

  const User = mongoose.model("User", usersSchema);

  // Initializing and using passport-local-mongoose (static authentication method, serialization and deserialization of model in local strtegy.)

  // passport.use(User.createStrategy());
  // passport.serializeUser(User.serializeUser());
  // passport.deserializeUser(User.deserializeUser());

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

  //   OAuth (verify function must call cb to complete authentication)
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets",
        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
      },
      function (accessToken, refreshToken, profile, cb) {
        User.findOne({ googleId: profile.id }).then((foundUser) => {
          console.log(foundUser);
          if (!foundUser) {
            const user = new User({
              googleId: profile.id,
            });
            user
              .save()
              .then(() => {
                return cb(null, user);
              })
              .catch((err) => {
                return cb(err);
              });
          }
          return cb(null, foundUser);
        });
      }
    )
  );

  //   APPS MAIN ROUTES
  app.get("/", (req, res) => {
    res.render("home");
  });

  //   Use passport to authenticate user using the google strategy that we established above.
  app.get(
    "/auth/google",
    passport.authenticate("google", { scope: "profile" })
  );

  //   Redirect user back to our app once they logged into google.
  //   Use the options(successRedirect and failureRedirect) in Passport authenticate function to specify routes.
  app.get(
    "/auth/google/secrets",
    passport.authenticate("google", {
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

  //   Secrets page access when the session exists
  //   Render "secrets" page if user is logged in, otherwise rediret user to the "login" page
  app.get("/secrets", (req, res) => {
    if (req.isAuthenticated()) {
      res.render("secrets");
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
  //   Register a user using passportLocalMongoose package. Allow user to access "/secrets" page after registration.
  app.post("/register", async (req, res) => {
    try {
      const registerUser = await User.register(
        { username: req.body.username },
        req.body.password
      );
      // use Passport to authenticate user:
      //   -- if user is successfully registered, then sets up a cookie and saves current login session
      //   so that user can automatically be able to view the "secrets" page if they are still loged in
      //   -- Otherwise, redirects user to "resgister" page and try again.
      if (registerUser) {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      } else {
        res.redirect("/register");
      }
    } catch {
      (err) => console.log(err);
    }
  });

  // Authenticate users using Passport, to access "/secrets" page after logged in.
  app.post("/login", (req, res) => {
    const user = new User({
      username: req.body.username,
      password: req.body.password,
    });

    console.log("0" + req.isAuthenticated());
    req.login(user, function (err) {
      if (err) {
        return next(err);
      } else {
        console.log("1" + req.isAuthenticated());
        passport.authenticate("local")(req, res, function () {
          console.log("2" + req.isAuthenticated());
          res.redirect("/secrets");
        });
      }
    });
  });

  app.listen(3000, () => {
    console.log("Server started on port 3000");
  });
}
