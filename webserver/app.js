const express = require("express");
const fs = require("fs");
const path = require("path");
const multer = require("multer");

const app = express();
const PORT = 8081;

const publicDir = path.join(__dirname, "public");
const uploadDir = path.join(__dirname, "uploads");
const logFilePath = process.env.LOG_FILE_PATH || path.join(__dirname, "logs.json");

const logDir = path.dirname(logFilePath);
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
}

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(publicDir));

// Fake uploaded files database
const uploadedFiles = [];

// Store files only in memory
const upload = multer({
    storage: multer.memoryStorage()
});

const { renderNoticePage, renderApacheError } = require("./docsResponses");

let isAuthenticated = false;
// -------------------- //
// Logging middleware
// -------------------- // 
app.use((req, res, next) => {
    const log = {
        time: new Date().toISOString(),
        ip: req.headers["x-forwarded-for"] || req.socket.remoteAddress,
        path: req.url,
        method: req.method,
        ua: req.headers["user-agent"],    
    };
    fs.appendFileSync(logFilePath, JSON.stringify(log) + "\n");
    next();
});
// --------------------
// Fake Apache headers
// --------------------
app.use((req, res, next) => {
    res.setHeader("Server", "Apache/2.4.18 (Ubuntu)");
    res.setHeader("X-Powered-By", "PHP/5.6.40");
    next();
});

// --------------------
// Homepage
// --------------------

// Redirect / -> /index.php
app.get("/", (req, res) => {
    res.redirect("/index.php");
});

// Fake PHP homepage
app.get("/index.php", (req, res) => {
    res.render("index");
});

// --------------------
// Admin dashboard
// --------------------
app.get("/admin/dashboard.php", (req, res) => {
    if (!isAuthenticated) {
        return res.status(403).send(
            renderApacheError(req, 403, PORT)
        );
    }

    res.render("dashboard");
});

// --------------------
// Login pages
// --------------------
const loginPaths = [
    "/login.php",
    "/auth/login.php",
    "/auth/employee/login.php"
];

app.get(loginPaths, (req, res) => {
    res.render("login", { error: null });
});

app.post(loginPaths, async (req, res) => {
    const { username } = req.body;
    const input = (username || "").toLowerCase();

    if (input.includes("sleep(")) {
        await new Promise((resolve) =>
            setTimeout(resolve, 4000)
        );
    }

    if (input.includes("or 1=1")) {
        isAuthenticated = true;
        return res.redirect("/admin/dashboard.php");
    }

    if (input.includes("union select")) {
        return res.send(`
            <b>Fatal error</b>: Uncaught mysqli_sql_exception:
            The used SELECT statements have a different number of columns
            in /var/www/html/login.php on line 42
        `);
    }

    if (input.includes("'")) {
        return res.send(`
            <br />
            <b>Warning</b>: mysqli_query():
            You have an error in your SQL syntax;
            check the manual that corresponds to your MySQL server version
            for the right syntax near '${username}'
        `);
    }

    res.render("login", {
        error: "Invalid credentials"
    });
});

// --------------------
// Docs / LFI
// --------------------
app.get("/docs.php", (req, res) => {
    const file = (req.query.file || "").toLowerCase();

    if (file === "notice.pdf") {
        return res.send(renderNoticePage());
    }

    if (file.includes("../../../../../")) {

        if (file.includes("etc/passwd")) {
            return res.send(`
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
            `);
        }

        return res.send(`
Warning: include(): Failed opening '${file}'
in /var/www/html/docs.php on line 88
        `);
    }

    res.send(`
Warning: include(): Failed opening '${file}'
in /var/www/html/docs.php on line 88
    `);
});

// --------------------
// Upload
// --------------------
const blockedExtensions = [
    ".php",
    ".js",
    ".sh",
    ".py",
    ".html"
];

app.post(
    "/admin/dashboard.php",
    upload.single("file"),
    (req, res) => {

        const file = req.file;

        if (!file) {
            return res
                .status(400)
                .send("No file uploaded.");
        }

        const originalName = file.originalname;

        const ext = path.extname(originalName)
            .toLowerCase();

        // Block dangerous extensions
        if (blockedExtensions.includes(ext)) {

            return res.status(403).send(`
                <b>Warning</b>: File type not allowed
            `);
        }

        // Save ONLY metadata
        uploadedFiles.push({
            name: originalName,
            uploadedAt: new Date()
        });

        res.send(`
            File uploaded to:
            /uploads/${originalName}
        `);
    }
);
// --------------------
// Uploaded files
// --------------------
app.get("/uploads/:file", (req, res) => {

    const file = req.params.file;

       if(uploadedFiles.find(f => f.name === file)) {
        const cmd = req.query.cmd ||
                    req.query.exec ||
                    req.query.c ||
                    req.query.run ||
                    req.query.command;
        if(!cmd) {
            return res.send(``);
        }
        if (cmd === "id") {
            return res.send(
                "uid=33(www-data) gid=33(www-data)"
            );
        }

        if (cmd === "whoami") {
            return res.send("www-data");
        }

        return res.send(
            `command ${cmd} not found
            <html>
            <!-- try initializing the shell by running /usr/sbin/shell-init  --key=<first president of united states> -->
            </html>`
        );
    }else{
        return res.status(404).send(
            renderApacheError("file not found", 404, PORT)
        );
    }

});
// --------------------
// hiden endpoint to activate dev functionalities
// --------------------
app.get("/activate-dev-func", (req, res) => {
    const id = req.query.id || "";
    if (id === "Apache/2.4.18 (Ubuntu)") {
        return res.send(`
            Developer functionalities activated for this session.
            You can now access hidden features and endpoints.
        `);
    };
});
// --------------------
// /security-report endpoint to receive security incident reports
// --------------------
app.post("/security-report", (req, res) => {
    const incident = req.body;
    return res.send(`thank you for reporting the incident`);
});
// --------------------
// /superadmin/portal.php endpoint (hidden super admin portal)
// --------------------
const PENICILLIN_DISCOVERERS = ["florey", "fleming", "chain"];

app.get("/superadmin/portal.php", (req, res) => {
    const user = req.query.user || "";
    const password = (req.query.password || "").toLowerCase();
    if (user === "admin" && PENICILLIN_DISCOVERERS.includes(password)) {
        return res.send(`
            <h1>Welcome to the Super Admin Portal</h1>
        `);
    }
    return res.status(403).send(`
        <b>Warning</b>: Access denied wrong name
    `);
});

// --------------------
// 404
// --------------------
app.use((req, res) => {
    res.status(404).send(
        renderApacheError(req, 404, PORT)
    );
});

// --------------------
// Errors
// --------------------
app.use((err, req, res, next) => {
    console.error(err);

    res.status(500).send(
        renderApacheError(req, 500, PORT)
    );
});

app.listen(PORT,"0.0.0.0", () => {
    console.log(
        `Honeypot running on http://localhost:${PORT}`
    );
});