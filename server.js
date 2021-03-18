const express = require("express");
const bodyParser = require("body-parser");
const db = require("./utils/db");
const { v4: uuidv4 } = require("uuid");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("config");
const auth = require("./middleware/auth");
const path = require("path");

const app = express();
app.use(bodyParser.json());

// Authentication & User Routes

app.get("/api/", auth, async (req, res) => {
  const id = req.user.id;

  try {
    const [
      rows,
      fields
    ] = await db.query("SELECT * FROM User WHERE user_id = ?", [id]);

    return res.json(rows[0]);
  } catch (err) {
    console.error(err);
    return res.status(500).send("Server Error");
  }
});

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

// Item routes

app.get("/api/item", auth, async (req, res) => {
  const id = req.user.id;

  try {
    const [
      rows,
      fields
    ] = await db.query("SELECT * FROM Item WHERE user_id = ?; ",
      [id]
    );
    return res.status(200).json(rows);
  } catch (err) {
    console.error(err);
    return res.status(500).send("Server Error");
  }
});

app.post("/api/item", auth, async (req, res) => {
  // Adds an item to the todo list
  const id = req.user.id;
  const form = req.body;

  try {
    await db.query("INSERT INTO Item (user_id, post_date, body)" +
      " VALUES (?, NOW(), ?)",
      [id, form.body]
    );

    return res.status(201).json({ msg: "Item added to list", success: true });
  } catch (err) {
    console.error(err);
    return res.status(500).send("Server Error");
  }
});

app.delete("/api/item/:id", auth, async (req, res) => {
  const user_id = req.user.id;
  const item_id = req.params.id;

  try {
    const [
      rows,
      fields
    ] = await db.query("SELECT user_id FROM Item WHERE user_id = ? AND item_id = ?",
      [user_id, item_id]
    );

    if (rows.length != 1)
      return res.status(401).json({ errors: [{ msg: "Sorry can't delete that item :(" }] });

    await db.query("DELETE FROM Item WHERE item_id = ?", [item_id]);

    return res.status(200).json({ msg: "Item was deleted", success: true });
  } catch (err) {
    console.error(err);
    return res.status(500).send("Server Error");
  }
});


if (process.env.NODE_ENV === "production") {
  app.use(express.static("client/build"));

  app.get("*", (req, res) => {
    return res.sendFile(path.resolve(__dirname, "client", "build", "index.html"));
  })
}



const PORT = process.env.PORT || 5000;
app.listen(PORT, console.log("Server started on port " + PORT));