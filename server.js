const express = require("express");
const bodyParser = require("body-parser");
const db = require("./utils/db");
const { v4: uuidv4 } = require("uuid");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("config");

const app = express();
app.use(bodyParser.json());

// Authentication & User Routes

app.post("/api/register", async (req, res) => {
  const form = req.body;

  try {
    const [rows, fields] = await db.query("SELECT user_id FROM User WHERE email = ?; ", [form.email]);

    // Checks if email has already been registered
    if (rows.length !== 0) {
      return res.status(403).json({ errors: [{ msg: "Cannot register the same email twice. " }] });
    }

    // Creates a secure hashed and salted password
    const salt = await bcrypt.genSalt(10);
    const hashPass = await bcrypt.hash(form.password, salt);

    // Creates an user id
    const id = uuidv4();

    // Creates a sercure hashed and salted password
    await db.query("INSERT INTO User (user_id, name, email, password, join_date, last_login_date) " +
      "VALUES (?, ?, ?, ?, NOW(), NOW())",
      [id, form.name, form.email, hashPass]);


    // Sign and sends an auth token
    const payload = {
      user: {
        id: id,
      },
    };

    jwt.sign(
      payload,
      config.get("jwtSecret"),
      { expiresIn: 7200 },
      (err, token) => {
        if (err) throw err;
        else return res.status(201).json({ token });
      }
    );
  } catch (err) {
    console.error(err);
    return res.status(500).send("Server Error");
  }
});

app.post("/api/login", async (req, res) => {
  const form = req.body;

  try {
    const [rows, fields] = await db.query("SELECT user_id, password FROM User WHERE email = ?; ", [form.email]);

    // Check if an email is registered
    if (rows.length !== 1)
      return res.status(400).json({ errors: [{ msg: "Invalid credentials" }] });

    const isMatch = await bcrypt.compare(form.password, rows[0].password);

    // Confirms that the user entered in the correct password 
    if (!isMatch) {
      return res.status(400).json({ errors: [{ msg: "Invalid credentials" }] });
    }

    // update last login for user
    await db.query("UPDATE User SET last_login_date = NOW() WHERE user_id = ?; ",
      [rows[0].user_id]);

    // Sign and sends an auth token
    const payload = {
      user: {
        id: rows[0].user_id,
      },
    };

    jwt.sign(
      payload,
      config.get("jwtSecret"),
      { expiresIn: 7200 },
      (err, token) => {
        if (err) throw err;
        else return res.status(200).json({ token });
      }
    );
  } catch (err) {
    console.error(err);
    return res.status(500).send("Server Error");
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, console.log("Server started on port " + PORT));