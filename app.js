// require dotenv and configure it to be able to access our env variables
require("dotenv").config();

const express = require("express");
const ejs = require("ejs");
const app = express();
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const saltRounds = 10;

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));

main().catch((err) => console.log(err));

async function main() {
  await mongoose.connect("mongodb://127.0.0.1:27017/userDB");

  const usersSchema = new mongoose.Schema({
    email: String,
    password: String,
  });

  const User = mongoose.model("User", usersSchema);

  app.get("/", (req, res) => {
    res.render("home");
  });
  app.get("/login", (req, res) => {
    res.render("login", { errMsg: "" });
  });
  app.get("/register", (req, res) => {
    res.render("register");
  });

  app.get("/secrets", (req, res) => {
    res.render("secrets");
  });

  //Allow user to access "/secrets" page after registration.
  app.post("/register", (req, res) => {
    bcrypt.hash(req.body.password, saltRounds, async (err, hash) => {
      const newUser = new User({
        email: req.body.username,
        password: hash,
      });

      await newUser
        .save()
        .then(() => {
          res.render("secrets");
        })
        .catch((err) => console.log(err));
    });
  });

  //allow user to access "/secrets" page after logged in.
  app.post("/login", async (req, res) => {
    try {
      const username = req.body.username;
      const password = req.body.password;
      const foundUser = await User.findOne({ email: username });
      if (foundUser) {
        bcrypt.compare(password, foundUser.password, function (err, result) {
          if (result == true) {
            res.render("secrets");
          } else {
            res.render("login", { errMsg: "Invalid username or password" });
          }
        });
      } else {
        res.render("login", { errMsg: "Invalid username or password" });
      }
    } catch {
      (err) => console.log(err);
    }
  });

  //use md5 to hash user's password when they registers and logs in.

  app.listen(3000, () => {
    console.log("Server started on port 3000");
  });
}
