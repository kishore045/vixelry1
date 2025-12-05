require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { MongoClient } = require('mongodb');

const app = express();
app.use(cors());
app.use(express.json());

// Read env values
const MONGO = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'secret';

// Debug: show whether MONGO_URI is present (mask sensitive parts)
if (!MONGO) {
  console.error('ERROR: MONGO_URI not set in .env');
} else {
  try {
    const masked = MONGO.replace(/(mongodb(?:\+srv)?:\/\/)(.*):(.*)@(.*)/, (m, p1, user, pass, rest) => {
      const maskedPass = pass ? '***' : '';
      return `${p1}${user}:${maskedPass}@${rest}`;
    });
    console.log('Using MONGO_URI:', masked);
  } catch (e) {
    console.log('Using MONGO_URI (raw, not masked):', typeof MONGO === 'string' ? ('[length ' + MONGO.length + ']') : MONGO);
  }
}

/*
  Debug-friendly MongoClient options.
  NOTE: tlsAllowInvalidCertificates bypasses certificate validation — DEBUG ONLY.
  Remove tlsAllowInvalidCertificates (or set to false) for production.
*/
const clientOptions = {
  tls: true,
  tlsAllowInvalidCertificates: true, // DEBUG ONLY: bypass cert validation on local dev if needed
  serverSelectionTimeoutMS: 10000
};

const client = new MongoClient(MONGO || '', clientOptions);

// optional: log the options being used (uncomment if you want more debug)
console.log('MongoClient options:', { tls: clientOptions.tls, tlsAllowInvalidCertificates: clientOptions.tlsAllowInvalidCertificates });

let usersColl;

async function init() {
  try {
    await client.connect();
    const db = client.db(process.env.DB_NAME || 'vixelry_db');
    usersColl = db.collection('users');
    console.log("MongoDB Connected ✔️");
  } catch (err) {
    console.error("Mongo Error ❌:", err);
  }
}
init();

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (!email || !password)
      return res.status(400).json({ message: "Missing fields" });

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

app.listen(4000, () => console.log("Auth Server Running on PORT 4000 ✔️"));
