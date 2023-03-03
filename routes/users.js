const express = require("express");
const Models = require("./../models");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const statusCode = require("../helpers/statusCode.js");
const User = Models.User;
dotenv.config();

const router = express.Router();

router.get("/", async (req, res, next) => {
  try {
    const users = await User.findAll();
    if (users) {
      res
        .status(statusCode.success)
        .json({ status: true, messages: "Fetch all users", users });
    } else {
      res
        .status(statusCode.not_found)
        .send({ status: false, error: "No users found" });
    }
  } catch (err) {
    res.status(statusCode.error).json({ status: false, error: err });
  }
});

router.post("/", async (req, res, next) => {
  try {
    const user = await User.findOne({ where: { email: req.body.email } });
    if (user) {
      res
        .status(statusCode.success)
        .json({ status: false, error: "User already exists" });
    } else {
      const salt = await bcrypt.genSalt(10);
      const payload = {
        firstname: req.body.firstname,
        lastname: req.body.lastname,
        email: req.body.email,
        password: await bcrypt.hash(req.body.password, salt),
        role: req.body.role.toLowerCase(),
      };
      created_user = await User.create(payload);
      res.status(201).json({
        status: true,
        messages: "User signup successfully",
        user: created_user,
      });
    }
  } catch (err) {
    res.status(statusCode.error).json({ status: false, error: err });
  }
});

router.post("/signin", async (req, res, next) => {
  try {
    const user = await User.findOne({ where: { email: req.body.email } });

    if (user) {
      if (user.role === "admin") {
        const password_valid = await bcrypt.compare(
          req.body.password,
          user.password
        );
        if (password_valid) {
          token = jwt.sign(
            { id: user.id, email: user.email, firstname: user.firstname },
            process.env.SECRET
          );
          res.status(statusCode.success).json({
            status: true,
            messages: "User signin successfully",
            token: token,
          });
        } else {
          res.status(400).json({ status: false, error: "Password Incorrect" });
        }
      } else {
        res.status(statusCode.success).json({
          status: false,
          error: "You are not allowed to login from here",
        });
      }
    } else {
      res
        .status(statusCode.success)
        .json({ status: false, error: "User does not exist" });
    }
  } catch (err) {
    res.status(statusCode.error).json({ status: false, error: err });
  }
});

module.exports = router;
