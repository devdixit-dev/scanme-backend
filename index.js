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

const normalizeValue = value =>
  value === undefined || value === null ? '' : String(value).trim();

const escapeWifiValue = value =>
  String(value).replace(/([\\;,:"])/g, '\\$1');

const unescapeWifiValue = value =>
  String(value).replace(/\\([\\;,:"])/g, '$1');

const toIcsDate = value => {
  const input = normalizeValue(value);
  if (!input) return '';

  if (/^\d{8}$/.test(input) || /^\d{8}T\d{6}Z?$/.test(input)) return input;

  const [datePart, timePart] = input.split('T');
  if (!datePart) return '';

  const date = datePart.replace(/-/g, '');
  if (!timePart) return date;

  const time = timePart.replace(/:/g, '').padEnd(6, '0');
  return `${date}T${time}`;
};

const fromIcsDate = value => {
  const input = normalizeValue(value);
  if (!input) return '';

  if (/^\d{8}$/.test(input)) {
    return `${input.slice(0, 4)}-${input.slice(4, 6)}-${input.slice(6, 8)}`;
  }

  if (/^\d{8}T\d{6}Z?$/.test(input)) {
    const date = `${input.slice(0, 4)}-${input.slice(4, 6)}-${input.slice(6, 8)}`;
    const time = `${input.slice(9, 11)}:${input.slice(11, 13)}`;
    return `${date}T${time}`;
  }

  return input;
};

function buildQRPayload(type, data) {
  const payload = typeof data === 'object' && data !== null ? data : {};
  const raw = typeof data === 'string' ? data : '';

  switch (type) {
    case 'url': {
      const url = normalizeValue(payload.url || raw);
      if (!url) return null;
      return { content: url, data: { url } };
    }
    case 'text': {
      const text = normalizeValue(payload.text || raw);
      if (!text) return null;
      return { content: text, data: { text } };
    }
    case 'wifi': {
      const ssid = normalizeValue(payload.ssid);
      const password = normalizeValue(payload.password);
      if (!ssid) return null;

      let encryption = normalizeValue(payload.encryption);
      const upper = encryption.toUpperCase();
      if (!password || upper === 'NOPASS' || upper === 'NONE') {
        encryption = 'nopass';
      } else if (upper === 'WEP') {
        encryption = 'WEP';
      } else {
        encryption = 'WPA';
      }

      const wifiParts = [
        `WIFI:T:${encryption};`,
        `S:${escapeWifiValue(ssid)};`,
        password ? `P:${escapeWifiValue(password)};` : '',
        ';'
      ];

      return {
        content: wifiParts.join(''),
        data: { ssid, password, encryption }
      };
    }
    case 'vcard': {
      const firstName = normalizeValue(payload.firstName);
      const lastName = normalizeValue(payload.lastName);
      const phone = normalizeValue(payload.phone);
      const email = normalizeValue(payload.email);
      const organization = normalizeValue(payload.organization);

      if (!firstName && !lastName && !phone && !email) return null;

      const fullName = [firstName, lastName].filter(Boolean).join(' ');
      const lines = [
        'BEGIN:VCARD',
        'VERSION:3.0',
        `N:${lastName};${firstName}`,
        fullName ? `FN:${fullName}` : null,
        organization ? `ORG:${organization}` : null,
        phone ? `TEL;TYPE=CELL:${phone}` : null,
        email ? `EMAIL:${email}` : null,
        'END:VCARD'
      ].filter(Boolean);

      return {
        content: lines.join('\n'),
        data: { firstName, lastName, phone, email, organization }
      };
    }
    case 'sms': {
      const number = normalizeValue(payload.number);
      const message = normalizeValue(payload.message);
      if (!number) return null;
      const content = `SMSTO:${number}${message ? `:${message}` : ''}`;
      return { content, data: { number, message } };
    }
    case 'call': {
      const number = normalizeValue(payload.number || raw);
      if (!number) return null;
      return { content: `tel:${number}`, data: { number } };
    }
    case 'mail': {
      const email = normalizeValue(payload.email || raw);
      if (!email) return null;
      const subject = normalizeValue(payload.subject);
      const body = normalizeValue(payload.body);

      const params = new URLSearchParams();
      if (subject) params.set('subject', subject);
      if (body) params.set('body', body);

      const query = params.toString();
      return {
        content: `mailto:${email}${query ? `?${query}` : ''}`,
        data: { email, subject, body }
      };
    }
    case 'location': {
      const latitude = normalizeValue(payload.latitude);
      const longitude = normalizeValue(payload.longitude);
      if (!latitude || !longitude) return null;
      return {
        content: `geo:${latitude},${longitude}`,
        data: { latitude, longitude }
      };
    }
    case 'event': {
      const title = normalizeValue(payload.title);
      const location = normalizeValue(payload.location);
      const startDate = normalizeValue(payload.startDate);
      const endDate = normalizeValue(payload.endDate);

      if (!title && !startDate && !endDate) return null;

      const lines = [
        'BEGIN:VCALENDAR',
        'VERSION:2.0',
        'BEGIN:VEVENT',
        title ? `SUMMARY:${title}` : null,
        location ? `LOCATION:${location}` : null,
        startDate ? `DTSTART:${toIcsDate(startDate)}` : null,
        endDate ? `DTEND:${toIcsDate(endDate)}` : null,
        'END:VEVENT',
        'END:VCALENDAR'
      ].filter(Boolean);

      return {
        content: lines.join('\n'),
        data: { title, location, startDate, endDate }
      };
    }
    default:
      return null;
  }
}

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

function parseQRData(rawData) {
  const data = normalizeValue(rawData);
  if (!data) return { type: 'text', parsed: { text: '' } };

  const lower = data.toLowerCase();
  if (lower.startsWith('http://') || lower.startsWith('https://')) {
    return { type: 'url', parsed: { url: data, text: data } };
  }

  if (lower.startsWith('wifi:')) {
    const payload = data.slice(5);
    const fields = payload.split(';').filter(Boolean);
    let ssid = '';
    let password = '';
    let encryption = '';

    fields.forEach(field => {
      const upperField = field.toUpperCase();
      if (upperField.startsWith('S:')) ssid = unescapeWifiValue(field.slice(2));
      if (upperField.startsWith('P:')) password = unescapeWifiValue(field.slice(2));
      if (upperField.startsWith('T:')) encryption = field.slice(2);
    });

    const encryptionUpper = encryption.toUpperCase();
    const normalizedEncryption = encryptionUpper === 'WEP' ? 'WEP' :
      (encryptionUpper === 'NOPASS' || encryptionUpper === 'NONE' || !encryptionUpper ? 'nopass' : 'WPA');

    const parts = [];
    if (ssid) parts.push(`SSID: ${ssid}`);
    if (password) parts.push(`Password: ${password}`);
    if (normalizedEncryption) parts.push(`Encryption: ${normalizedEncryption}`);

    return {
      type: 'wifi',
      parsed: {
        ssid,
        password,
        encryption: normalizedEncryption,
        text: parts.length ? parts.join(' | ') : data
      }
    };
  }

  if (lower.startsWith('begin:vcard')) {
    const lines = data.split(/\r?\n/);
    let firstName = '';
    let lastName = '';
    let fullName = '';
    let phone = '';
    let email = '';
    let organization = '';

    lines.forEach(line => {
      const [left, ...rest] = line.split(':');
      const key = left.split(';')[0].toUpperCase();
      const value = rest.join(':').trim();

      if (key === 'N') {
        const [last, first] = value.split(';');
        lastName = lastName || normalizeValue(last);
        firstName = firstName || normalizeValue(first);
      }
      if (key === 'FN') fullName = normalizeValue(value);
      if (key === 'TEL') phone = normalizeValue(value);
      if (key === 'EMAIL') email = normalizeValue(value);
      if (key === 'ORG') organization = normalizeValue(value);
    });

    const displayName = fullName || [firstName, lastName].filter(Boolean).join(' ');
    const parts = [displayName, phone, email].filter(Boolean);

    return {
      type: 'vcard',
      parsed: {
        firstName,
        lastName,
        phone,
        email,
        organization,
        text: parts.length ? parts.join(' | ') : data
      }
    };
  }

  if (lower.startsWith('smsto:') || lower.startsWith('sms:')) {
    const payload = data.replace(/^smsto:/i, '').replace(/^sms:/i, '');
    const [numberPart, messagePart] = payload.split(':');
    const number = normalizeValue(numberPart);
    const message = normalizeValue(messagePart);
    const text = [number, message].filter(Boolean).join(' - ');

    return {
      type: 'sms',
      parsed: { number, message, text: text || data }
    };
  }

  if (lower.startsWith('tel:')) {
    const number = data.slice(4);
    return {
      type: 'call',
      parsed: { number, text: number }
    };
  }

  if (lower.startsWith('mailto:')) {
    const payload = data.replace(/^mailto:/i, '');
    const [address, query] = payload.split('?');
    const params = new URLSearchParams(query || '');
    const subject = normalizeValue(params.get('subject'));
    const body = normalizeValue(params.get('body'));
    const parts = [
      normalizeValue(address),
      subject ? `Subject: ${subject}` : '',
      body ? `Body: ${body}` : ''
    ].filter(Boolean);

    return {
      type: 'mail',
      parsed: {
        email: normalizeValue(address),
        subject,
        body,
        text: parts.length ? parts.join(' | ') : data
      }
    };
  }

  if (lower.startsWith('geo:')) {
    const payload = data.replace(/^geo:/i, '').split('?')[0];
    const [lat, lon] = payload.split(',');
    const latitude = normalizeValue(lat);
    const longitude = normalizeValue(lon);

    return {
      type: 'location',
      parsed: {
        latitude,
        longitude,
        text: latitude && longitude ? `${latitude}, ${longitude}` : data
      }
    };
  }

  const upper = data.toUpperCase();
  if (upper.includes('BEGIN:VEVENT') || upper.includes('BEGIN:VCALENDAR')) {
    const lines = data.split(/\r?\n/);
    let title = '';
    let location = '';
    let startDate = '';
    let endDate = '';

    lines.forEach(line => {
      const [left, ...rest] = line.split(':');
      const key = left.split(';')[0].toUpperCase();
      const value = rest.join(':').trim();

      if (key === 'SUMMARY') title = normalizeValue(value);
      if (key === 'LOCATION') location = normalizeValue(value);
      if (key === 'DTSTART') startDate = fromIcsDate(value);
      if (key === 'DTEND') endDate = fromIcsDate(value);
    });

    const parts = [
      title,
      location ? `Location: ${location}` : '',
      startDate ? `Start: ${startDate}` : '',
      endDate ? `End: ${endDate}` : ''
    ].filter(Boolean);

    return {
      type: 'event',
      parsed: {
        title,
        location,
        startDate,
        endDate,
        text: parts.length ? parts.join(' | ') : data
      }
    };
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

  const imageUrl = `${process.env.BACKEND_URL}/uploads/${req.file.filename}`;

  const record = await ScanHistory.create({
    userId: req.userId,
    qrType: parsed.type,
    qrData,
    decodedData: parsed.parsed,
    imageUrl
  });

  res.json({ success: true, data: record });
});

app.post('/api/generate', async (req, res) => {
  const { type, data } = req.body;
  if (!type || !data) {
    return res.status(400).json({ success: false, error: 'Invalid input' });
  }

  const payload = buildQRPayload(type, data);
  if (!payload) {
    return res.status(400).json({ success: false, error: 'Unsupported or incomplete payload' });
  }

  const { content, data: normalizedData } = payload;
  const filename = `qr-${Date.now()}.png`;
  const outPath = path.join(QR_OUTPUT_DIR, filename);

  await QRCode.toFile(outPath, content);

  const imageUrl = `${process.env.BACKEND_URL}/qr-codes/${filename}`;

  const record = await QRGeneration.create({
    userId: req.userId,
    qrType: type,
    data: normalizedData,
    imageUrl
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
