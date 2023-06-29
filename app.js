// require dotenv and configure it to be able to access our env variables
require("dotenv").config();

const express = require("express");
const ejs = require("ejs");
const app = express();
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));

// set up session and passport with some initial configurations.
app.use(
  session({
    secret: "This is our secret.",
    resave: false,
    saveUninitialized: true,
  })
);

app.use(passport.initialize());
app.use(passport.session());

main().catch((err) => console.log(err));

async function main() {
  await mongoose.connect("mongodb://127.0.0.1:27017/userDB");

  const usersSchema = new mongoose.Schema({
    email: String,
    password: String,
  });

  //   Hash and salt passwords and save our users to DB
  usersSchema.plugin(passportLocalMongoose);

  const User = mongoose.model("User", usersSchema);

  // use passport to create a local login strategy. (static authenticate method of model in LocalStrategy)
  passport.use(User.createStrategy());

  // use static serialize and deserialize of model for passport session support
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

  app.get("/", (req, res) => {
    res.render("home");
  });
  app.get("/login", (req, res) => {
    res.render("login", { errMsg: "" });
  });
  app.get("/register", (req, res) => {
    res.render("register");
  });

  //   Render "secrets" page if user is logged in, otherwise rediret user to the "login" page
  app.get("/secrets", (req, res) => {
    if (req.isAuthenticated()) {
      res.render("secrets");
    } else {
      res.redirect("/login");
    }
  });

  //   Logout user once they clicked logout button, end their session and redirect to home page.
  app.get("/logout", (req, res, next) => {
    req.logout(function (err) {
      if (err) {
        return next(err);
      } else {
        res.redirect("/");
      }
    });
  });

  //Register a user using passportLocalMongoose package. Allow user to access "/secrets" page after registration.
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

    req.login(user, function (err) {
      if (err) {
        return next(err);
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    });
  });

  app.listen(3000, () => {
    console.log("Server started on port 3000");
  });
}
