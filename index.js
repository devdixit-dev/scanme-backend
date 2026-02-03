import 'dotenv/config';
import express from 'express';
import mongoose from 'mongoose';
import multer from 'multer';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import { createHash } from 'crypto';
import QRCode from 'qrcode';
import Jimp from 'jimp';
import jsQR from 'jsqr';

const __dirname = process.cwd();

/* =====================================================
   EXPRESS APP SETUP
===================================================== */

const app = express();
const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI;
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const QR_OUTPUT_DIR = path.join(__dirname, 'qr-codes');

[UPLOAD_DIR, QR_OUTPUT_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true
}));

app.options("*", cors());

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.use('/uploads', express.static(UPLOAD_DIR));
app.use('/qr-codes', express.static(QR_OUTPUT_DIR));

/* =====================================================
   MONGOOSE SCHEMAS
===================================================== */

const { Schema } = mongoose;

const UserSchema = new Schema({
  userId: { type: String, required: true, unique: true, index: true },
  email: { type: String, sparse: true },
  createdAt: { type: Date, default: Date.now },
  lastActive: { type: Date, default: Date.now }
});

const ScanHistorySchema = new Schema({
  userId: String,
  qrType: String,
  qrData: String,
  decodedData: Schema.Types.Mixed,
  imageUrl: String,
  scannedAt: { type: Date, default: Date.now },
  metadata: {
    userAgent: String,
    ip: String,
    device: String
  }
});

const QRGenerationSchema = new Schema({
  userId: String,
  qrType: String,
  data: Schema.Types.Mixed,
  imageUrl: String,
  generatedAt: { type: Date, default: Date.now }
});

const AnalyticsSchema = new Schema({
  date: { type: Date, unique: true },
  totalScans: { type: Number, default: 0 },
  totalGenerations: { type: Number, default: 0 },
  uniqueUsers: { type: Number, default: 0 },
  qrTypeBreakdown: { type: Map, of: Number, default: {} }
});

/* =====================================================
   MODELS
===================================================== */

const User = mongoose.model('User', UserSchema);
const ScanHistory = mongoose.model('ScanHistory', ScanHistorySchema);
const QRGeneration = mongoose.model('QRGeneration', QRGenerationSchema);
const Analytics = mongoose.model('Analytics', AnalyticsSchema);

/* =====================================================
   MIDDLEWARE
===================================================== */

app.use((req, _, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
  next();
});

app.use(async (req, _, next) => {
  try {
    let userId = req.headers['x-user-id'];

    if (!userId) {
      const identifier = `${req.ip}-${req.headers['user-agent']}`;
      userId = createHash('sha256').update(identifier).digest('hex').slice(0, 16);
    }

    await User.findOneAndUpdate(
      { userId },
      { userId, lastActive: new Date() },
      { upsert: true }
    );

    req.userId = userId;
    next();
  } catch (err) {
    console.error('User tracking error', err);
    next();
  }
});

/* =====================================================
   MULTER CONFIG
===================================================== */

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOAD_DIR),
  filename: (_, file, cb) => {
    const unique = Date.now() + '-' + Math.random().toString(36).slice(2);
    cb(null, `${file.fieldname}-${unique}${path.extname(file.originalname)}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter(_, file, cb) {
    const allowed = ['image/png', 'image/jpeg', 'image/jpg', 'image/webp'];
    cb(null, allowed.includes(file.mimetype));
  }
});

/* =====================================================
   HELPERS
===================================================== */

async function decodeQRFromImage(imagePath) {
  try {
    const image = await Jimp.read(imagePath);
    image.grayscale().contrast(0.3);

    const { data, width, height } = image.bitmap;

    const code = jsQR(
      new Uint8ClampedArray(data),
      width,
      height,
      { inversionAttempts: 'attemptBoth' }
    );

    return code ? code.data : null;
  } catch {
    return null;
  }
}

function parseQRData(data) {
  if (data.startsWith('http')) return { type: 'url', parsed: { url: data } };
  if (data.startsWith('tel:')) return { type: 'call', parsed: { number: data.slice(4) } };
  if (data.startsWith('smsto:')) {
    const [number, message] = data.slice(6).split(':');
    return { type: 'sms', parsed: { number, message } };
  }
  return { type: 'text', parsed: { text: data } };
}

/* =====================================================
   ROUTES
===================================================== */

app.get('/api/health', (_, res) => {
  res.json({ success: true, message: 'ScanQR Backend running' });
});

app.post('/api/scan/upload', upload.single('qrImage'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, error: 'No file uploaded' });
  }

  const qrData = await decodeQRFromImage(req.file.path);
  if (!qrData) {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ success: false, error: 'QR not detected' });
  }

  const parsed = parseQRData(qrData);

  const record = await ScanHistory.create({
    userId: req.userId,
    qrType: parsed.type,
    qrData,
    decodedData: parsed.parsed,
    imageUrl: `/uploads/${req.file.filename}`
  });

  res.json({ success: true, data: record });
});

app.post('/api/generate', async (req, res) => {
  const { type, data } = req.body;
  if (!type || !data) {
    return res.status(400).json({ success: false, error: 'Invalid input' });
  }

  const content = typeof data === 'string' ? data : JSON.stringify(data);
  const filename = `qr-${Date.now()}.png`;
  const outPath = path.join(QR_OUTPUT_DIR, filename);

  await QRCode.toFile(outPath, content);

  const record = await QRGeneration.create({
    userId: req.userId,
    qrType: type,
    data,
    imageUrl: `/qr-codes/${filename}`
  });

  res.json({ success: true, data: record });
});

/* =====================================================
   ERROR HANDLER
===================================================== */

app.use((err, _, res, __) => {
  console.error(err);
  res.status(500).json({ success: false, error: err.message });
});

/* =====================================================
   SERVER START
===================================================== */

mongoose.connect(MONGO_URI, { dbName: 'scanme_db' })
  .then(() => {
    console.log('✅ MongoDB connected');
    app.listen(PORT, () =>
      console.log(`🚀 Server running on http://localhost:${PORT}`)
    );
  })
  .catch(err => {
    console.error('❌ MongoDB error', err);
    process.exit(1);
  });

export default app;
