import arcjet, { validateEmail, tokenBucket, detectBot  } from "@arcjet/node";
import { isSpoofedBot } from "@arcjet/inspect";
import express from "express";
import session from "express-session";
import { configDotenv } from "dotenv";

configDotenv();

const app = express();
const port = 3000;

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
    }),
    tokenBucket({
      mode: "LIVE", // Set to "DRY_RUN" to test without blocking
      characteristics: ["userId"], // Track requests per user
      refillRate: 5, // Tokens refilled every interval
      interval: 30, // Interval (seconds)
      capacity: 10, // Max tokens
    }),
    detectBot({
      mode: "LIVE", // will block requests. Use "DRY_RUN" to log only
      // Block all bots except the following
      allow: [
        "CATEGORY:SEARCH_ENGINE", // Google, Bing, etc
        // Uncomment to allow these other common bot categories
        // See the full list at https://arcjet.com/bot-list
        //"CATEGORY:MONITOR", // Uptime monitoring services
        //"CATEGORY:PREVIEW", // Link previews e.g. Slack, Discord
      ],
    }),
  ],
});

const displayEmails = () => {
  console.log("Registered users:");
  users.forEach((user) => console.log(user.email));
};

app.post("/signup", async (req, res) => {
  try {
    const { email, password } = req.body;

    const decision = await aj.protect(req, {
      userId:email,
      email,
      requested: 5, // consumes 5 tokens per request
    });

    console.log("Arcjet decision:", decision);

    if (decision.isDenied() || decision.isSpoofedBot()) {
      res.writeHead(403, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ error: "Forbidden",message:decision.conclusion }));
    }

    if (users.find((user) => user.email === email)) {
      return res.status(400).json({ message: "User already exists" });
    }

    users.push({ email, password });

    displayEmails();

    return res.status(200).json({
      message: "Signup successful",
      email,
    });
  } catch (error) {
    console.error("Signup error:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
