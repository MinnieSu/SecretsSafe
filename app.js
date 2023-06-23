// reuqire dotenv and configure it to be able to access our env varibles
require("dotenv").config();

const express = require("express");
const ejs = require("ejs");
const app = express();
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");

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

  usersSchema.plugin(encrypt, {
    secret: process.env.SECRET,
    encryptedFields: ["password"],
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
  app.post("/register", async (req, res) => {
    const newUser = new User({
      email: req.body.username,
      password: req.body.password,
    });

    await newUser
      .save()
      .then(() => {
        res.render("secrets");
      })
      .catch((err) => console.log(err));
  });

  //allow user to access "/secrets" page after logged in.
  app.post("/login", async (req, res) => {
    try {
      const username = req.body.username;
      const password = req.body.password;
      const foundUser = await User.findOne({ email: username });
      if (foundUser) {
        if (foundUser.password === password) {
          res.render("secrets");
        } else {
          res.render("login", { errMsg: "Invalid username or password" });
        }
      } else {
        res.render("login", { errMsg: "Invalid username or password" });
      }
    } catch {
      (err) => console.log(err);
    }
  });

  app.listen(3000, () => {
    console.log("Server started on port 3000");
  });
}
