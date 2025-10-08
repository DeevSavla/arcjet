import arcjet, { validateEmail } from "@arcjet/node";
import express from "express";
import session from "express-session";
import { configDotenv } from "dotenv";

configDotenv();

const app = express();

const port = 3000;

//in memory
const users = [];

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: "keyboard cat",
    resave: false,
    saveUninitialized: false,
  })
);

const aj = arcjet({
  key: process.env.ARCJET_KEY,
  rules: [
    validateEmail({
      mode: "LIVE",
      deny: ["DISPOSABLE", "INVALID", "NO_MX_RECORDS"],
      //MX Record is a type of DNS record that specifies which mail server is responsible for receiving emails for a domain, acting as the digital address for incoming mail
    }),
  ],
});

const displayEmails = () => {
  console.log("Registered user");
  users.forEach((user) => console.log(user.email));
};

app.post("/signup", async (req, res) => {
  try {
    const { email, password } = req.body;

    const decision = await aj.protect(req, {
      email,
    });
    console.log("Arcjet decision", decision);

    if (decision.isDenied()) {
      res.writeHead(403, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ error: "Forbidden" }));
    }

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ message: "Hello World", email: req.body.email }));

    if (users.find((user) => user.email === email)) {
      return res.status(400).json({
        message: "User already exists",
      });
    }
  } catch (error) {
    console.log(error)
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
