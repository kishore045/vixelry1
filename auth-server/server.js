require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { MongoClient } = require('mongodb');

const app = express();
app.use(cors());
app.use(express.json());

// Read env values
const MONGO = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'secret';
const DB_NAME = process.env.DB_NAME || 'vixelry_db';
const PORT = process.env.PORT || 4000; // use HOST provided PORT

// Debug: mask MONGO
if (!MONGO) {
  console.error('ERROR: MONGO_URI not set in env');
} else {
  try {
    const masked = MONGO.replace(/(mongodb(?:\+srv)?:\/\/)(.*):(.*)@(.*)/, (m,p1,user,pass,rest)=> {
      const mp = pass ? '***' : '';
      return `${p1}${user}:${mp}@${rest}`;
    });
    console.log('Using MONGO_URI:', masked);
  } catch(e) {
    console.log('Using MONGO_URI length:', typeof MONGO === 'string' ? MONGO.length : MONGO);
  }
}

const clientOptions = {
  tls: true,
  // NOTE: tlsAllowInvalidCertificates: true is potentially unsafe. Remove or set false in prod.
  tlsAllowInvalidCertificates: false,
  serverSelectionTimeoutMS: 10000
};

const client = new MongoClient(MONGO || '', clientOptions);

let usersColl;

// Initialize DB first, then start server
async function init() {
  try {
    await client.connect();
    const db = client.db(DB_NAME);
    usersColl = db.collection('users');
    console.log("MongoDB Connected ✔️");

    // start server only after DB connected
    app.listen(PORT, () => console.log(`Auth Server Running on PORT ${PORT} ✔️`));
  } catch (err) {
    console.error("Mongo Error ❌:", err);
    // If DB connect fails, exit (or retry logic could be added)
    process.exit(1);
  }
}
init();

/* --- routes --- */
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Missing fields" });

    const exists = await usersColl.findOne({ email });
    if (exists) return res.status(400).json({ message: "Email exists" });

    const hashed = await bcrypt.hash(password, 10);
    const result = await usersColl.insertOne({
      email,
      password: hashed,
      name: name || "",
      createdAt: new Date()
    });

    const token = jwt.sign({ uid: result.insertedId, email }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await usersColl.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid login" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ message: "Invalid password" });

    const token = jwt.sign({ uid: user._id, email }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/auth/verify', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: "No token" });
  const token = auth.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return res.json({ ok: true, decoded });
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
});
