import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import env from "dotenv";


const app = express();
const port = 3000;
const saltRounds = 10;
env.config();


app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(session({
    secret: "privet",
    resave: false,
    saveUninitialized: true
}));
app.set("view engine", "ejs");

const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
  });
db.connect();
env.config();

// Middleware to check if the user is logged in
const requireLogin = (req, res, next) => {
    if (!req.session || !req.session.user || !req.session.user.email) {
        res.redirect("/login");
    } else {
        next();
    }
};

app.get("/", (req, res) => {
    res.render("home.ejs", { user: req.session.user, userPost: req.session.userPost });
});

app.get("/login", (req, res) => {
    res.render("login.ejs");
});

app.get("/register", (req, res) => {
    res.render("register.ejs");
});

app.post("/login", async (req, res) => {
    const email = req.body.username;
    const password = req.body.password;

    try {
        const userResult = await db.query("SELECT * FROM myusers WHERE email = $1", [email]);

        if (userResult.rows.length > 0) {
            const user = userResult.rows[0];

            bcrypt.compare(password, user.password, (err, result) => {
                if (err) {
                    console.error("Error comparing passwords:", err);
                    res.redirect("/login");
                } else {
                    if (result) {
                        req.session.user = user;
                        res.redirect("/index");
                    } else {
                        res.redirect("/login");
                    }
                }
            });
        } else {
            res.redirect("/login");
        }
    } catch (err) {
        console.log(err);
    }
});

app.post("/register", async (req, res) => {
    const email = req.body.username;
    const password = req.body.password;

    try {
        const checkResult = await db.query("SELECT * FROM myusers WHERE email = $1", [email]);

        if (checkResult.rows.length > 0) {
            res.redirect("/login");
        } else {
            bcrypt.hash(password, saltRounds, async (err, hash) => {
                if (err) {
                    console.error("Error hashing password:", err);
                } else {
                    const result = await db.query(
                        "INSERT INTO myusers (email, password) VALUES ($1, $2) RETURNING *",
                        [email, hash]
                    );
                    const user = result.rows[0];
                    req.session.user = user;
                    res.redirect("/index");
                }
            });
        }
    } catch (err) {
        console.log(err);
    }
});

app.get("/index", requireLogin, async (req, res) => {
    try {
        const userEmail = req.session.user.email;
        const userPostResult = await db.query("SELECT post FROM myusers WHERE email = $1", [userEmail]);
        req.session.userPost = userPostResult.rows[0]?.post;
        res.render("index.ejs", { user: req.session.user, userPost: req.session.userPost });
    } catch (err) {
        console.error("Error fetching user's post:", err);
        res.status(500).send("Internal Server Error");
    }
});

app.post("/submit", requireLogin, async (req, res) => {
    const userEmail = req.session.user.email;
    const secretText = req.body.secret;

    try {
        const existingUser = await db.query("SELECT * FROM myusers WHERE email = $1", [userEmail]);

        if (existingUser.rows.length > 0) {
            await db.query("UPDATE myusers SET post = $1 WHERE email = $2", [secretText, userEmail]);
        } else {
            await db.query("INSERT INTO myusers (email, post) VALUES ($1, $2)", [userEmail, secretText]);
        }

        res.redirect("/index");  // Redirect to the home page
    } catch (err) {
        console.error("Error saving post:", err);
        res.status(500).send("Internal Server Error");
    }
});

app.get("/logout", (req, res) => {
    // Destroy the user's session
    req.session.destroy((err) => {
        if (err) {
            console.error("Error destroying session:", err);
        }
        res.redirect("/"); // Redirect to the login page after logout
    });
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
