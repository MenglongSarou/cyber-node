<?php
session_start();

$db = new PDO('sqlite:/var/lib/cyber-node/app.sqlite');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->exec('PRAGMA busy_timeout = 5000');

$db->exec("
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
");

$db->exec("
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        event_type TEXT NOT NULL,
        ip TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
");

function e($value) {
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

function recordEvent($db, $username, $type) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $stmt = $db->prepare(
        'INSERT INTO events (username, event_type, ip)
         VALUES (?, ?, ?)'
    );
    $stmt->execute([$username, $type, $ip]);
}

if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = $_POST['csrf'] ?? '';

    if (!is_string($token) ||
        !hash_equals($_SESSION['csrf'], $token)) {
        $error = 'Invalid request. Refresh the page and try again.';
    } else {
        $action = $_POST['action'] ?? '';

        if ($action === 'login') {
            $username = trim($_POST['username'] ?? '');
            $password = $_POST['password'] ?? '';
            $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

            // Limit repeated failed logins from the same IP.
            $stmt = $db->prepare("
                SELECT COUNT(*) FROM events
                WHERE ip = ?
                AND event_type = 'LOGIN_FAILED'
                AND created_at >= datetime('now', '-5 minutes')
            ");
            $stmt->execute([$ip]);
            $failures = (int)$stmt->fetchColumn();

            if ($failures >= 10) {
                $error = 'Too many failed attempts. Wait five minutes.';
                recordEvent($db, $username, 'LOGIN_RATE_LIMITED');
            } else {
                $stmt = $db->prepare(
                    'SELECT id, username, password_hash
                     FROM users WHERE username = ?'
                );
                $stmt->execute([$username]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);

                if ($user &&
                    password_verify($password, $user['password_hash'])) {

                    session_regenerate_id(true);
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['username'] = $user['username'];
                    $_SESSION['csrf'] = bin2hex(random_bytes(32));

                    recordEvent($db, $user['username'], 'LOGIN_SUCCESS');

                    header('Location: index.php');
                    exit;
                } else {
                    recordEvent($db, $username, 'LOGIN_FAILED');
                    $error = 'Invalid username or password.';
                }
            }
        }

        if ($action === 'logout') {
            if (!empty($_SESSION['username'])) {
                recordEvent(
                    $db,
                    $_SESSION['username'],
                    'LOGOUT'
                );
            }

            $_SESSION = [];
            session_destroy();

            header('Location: index.php');
            exit;
        }
    }
}

$loggedIn = isset($_SESSION['user_id']);

$events = [];
if ($loggedIn) {
    $stmt = $db->query("
        SELECT username, event_type, ip, created_at
        FROM events ORDER BY id DESC LIMIT 20
    ");
    $events = $stmt->fetchAll(PDO::FETCH_ASSOC);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CYBER NODE // LOCALHOST</title>

<style>
* { box-sizing: border-box; margin: 0; padding: 0; }

body {
    background: #050505;
    color: #00ff88;
    font-family: "Courier New", monospace;
    min-height: 100vh;
    padding: 30px 15px;
    display: flex;
    justify-content: center;
    align-items: center;
}

body::before {
    content: "";
    position: fixed;
    inset: 0;
    background:
      linear-gradient(rgba(0,255,136,.045) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,255,136,.045) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
}

.container {
    width: 100%;
    max-width: 900px;
    padding: 35px;
    background: rgba(0,0,0,.94);
    border: 1px solid #00ff88;
    box-shadow: 0 0 25px rgba(0,255,136,.16);
    position: relative;
}

.terminal { color: #777; margin-bottom: 18px; }
h1 { font-size: clamp(30px, 6vw, 52px); letter-spacing: 5px; text-shadow: 0 0 14px #00ff88; }
.subtitle { color: #999; margin: 12px 0 28px; }
.line { height: 1px; background: #00ff88; opacity: .3; margin: 25px 0; }

.status {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 12px;
    margin: 22px 0;
}

.box {
    border: 1px solid #164f38;
    padding: 18px;
    background: rgba(0,255,136,.035);
    overflow-wrap: anywhere;
}

.box h3 { color: #777; font-size: 12px; margin-bottom: 10px; }
.box p { color: #00ff88; }

form { margin-top: 20px; }
label { display: block; color: #aaa; margin: 15px 0 7px; }

input {
    width: 100%;
    padding: 12px;
    background: #080d0a;
    color: #00ff88;
    border: 1px solid #1b6a48;
    font: inherit;
    outline: none;
}

input:focus { border-color: #00ff88; box-shadow: 0 0 8px #004d2a; }

button {
    margin-top: 20px;
    padding: 12px 18px;
    width: 100%;
    color: #001b0e;
    background: #00ff88;
    border: 0;
    font: bold 15px "Courier New", monospace;
    cursor: pointer;
}

button:hover { background: #9dffcc; }

.error {
    color: #ff7777;
    border: 1px solid #8b3030;
    padding: 12px;
    margin-top: 15px;
    overflow-wrap: anywhere;
}

table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 12px; }
th, td { text-align: left; padding: 10px 6px; border-bottom: 1px solid #173b2b; overflow-wrap: anywhere; }
th { color: #888; }
.footer { color: #555; font-size: 12px; margin-top: 30px; }

@media (max-width: 550px) {
    .container { padding: 20px 14px; }
    h1 { letter-spacing: 2px; }
    table { font-size: 10px; }
    th, td { padding: 8px 3px; }
}
</style>
</head>

<body>
<main class="container">

    <div class="terminal">root@localhost:~$ system_status</div>
    <h1>CYBER NODE</h1>
    <p class="subtitle">// Secure local environment initialized</p>

    <div class="line"></div>

    <?php if (!$loggedIn): ?>

        <p>AUTHENTICATION REQUIRED_</p>
        <p class="subtitle">Enter your credentials to access the node.</p>

        <?php if ($error !== ''): ?>
            <div class="error"><?= e($error) ?></div>
        <?php endif; ?>

        <form method="POST" action="index.php">
            <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
            <input type="hidden" name="action" value="login">

            <label for="username">USERNAME</label>
            <input id="username" name="username"
                   maxlength="64" autocomplete="username" required>

            <label for="password">PASSWORD</label>
            <input id="password" type="password" name="password"
                   autocomplete="current-password" required>

            <button type="submit">[ AUTHENTICATE ]</button>
        </form>

        <div class="status">
            <div class="box"><h3>SERVER</h3><p>APACHE2</p></div>
            <div class="box"><h3>DATABASE</h3><p>SQLITE</p></div>
            <div class="box"><h3>ACCESS</h3><p>RESTRICTED</p></div>
        </div>

    <?php else: ?>

        <p>ACCESS GRANTED_</p>
        <p class="subtitle">Welcome back, <?= e($_SESSION['username']) ?>.</p>

        <div class="status">
            <div class="box"><h3>SESSION</h3><p>AUTHENTICATED</p></div>
            <div class="box"><h3>DATABASE</h3><p>CONNECTED</p></div>
            <div class="box"><h3>SECURITY LOG</h3><p><?= count($events) ?> RECENT EVENTS</p></div>
        </div>

        <div class="line"></div>
        <h3> // SECURITY EVENT MONITOR</h3>
        <p class="subtitle">Recent login and logout activity recorded by this application.</p>

        <table>
            <thead>
                <tr>
                    <th>TIME (UTC)</th>
                    <th>USER</th>
                    <th>EVENT</th>
                    <th>IP ADDRESS</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($events as $event): ?>
                <tr>
                    <td><?= e($event['created_at']) ?></td>
                    <td><?= e($event['username']) ?></td>
                    <td><?= e($event['event_type']) ?></td>
                    <td><?= e($event['ip']) ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>

        <form method="POST" action="index.php">
            <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
            <input type="hidden" name="action" value="logout">
            <button type="submit">[ DISCONNECT ]</button>
        </form>

    <?php endif; ?>

    <div class="line"></div>
    <p class="terminal">root@localhost:~$ echo "Monitor. Detect. Defend."</p>
    <p class="footer">CYBER LAB // LOCALHOST // AUTHORIZED TESTING ONLY</p>
</main>
</body>
</html>
