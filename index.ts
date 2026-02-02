import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import mongoose, { Schema, Document } from 'mongoose';
import multer from 'multer';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import { createHash } from 'crypto';
import QRCode from 'qrcode';
import Jimp from 'jimp';
import jsQR from 'jsqr';

// ============================================
// TYPES & INTERFACES
// ============================================

interface IUser extends Document {
  userId: string;
  email?: string;
  createdAt: Date;
  lastActive: Date;
}

interface IScanHistory extends Document {
  userId: string;
  qrType: string;
  qrData: string;
  decodedData: any;
  imageUrl?: string;
  scannedAt: Date;
  metadata: {
    userAgent?: string;
    ip?: string;
    device?: string;
  };
}

interface IQRGeneration extends Document {
  userId: string;
  qrType: 'url' | 'text' | 'wifi' | 'vcard' | 'sms' | 'call' | 'event' | 'mail' | 'location';
  data: any;
  imageUrl: string;
  generatedAt: Date;
}

interface IAnalytics extends Document {
  date: Date;
  totalScans: number;
  totalGenerations: number;
  uniqueUsers: number;
  qrTypeBreakdown: Map<string, number>;
}

type QRType = 'url' | 'text' | 'wifi' | 'vcard' | 'sms' | 'call' | 'event' | 'mail' | 'location';

interface WiFiData {
  ssid: string;
  password: string;
  encryption: 'WPA' | 'WEP' | 'nopass';
  hidden?: boolean;
}

interface VCardData {
  firstName: string;
  lastName: string;
  organization?: string;
  title?: string;
  phone?: string;
  email?: string;
  url?: string;
  address?: string;
}

interface EventData {
  title: string;
  location?: string;
  description?: string;
  startDate: string;
  endDate: string;
}

// ============================================
// MONGODB SCHEMAS
// ============================================

const UserSchema = new Schema<IUser>({
  userId: { type: String, required: true, unique: true, index: true },
  email: { type: String, sparse: true },
  createdAt: { type: Date, default: Date.now },
  lastActive: { type: Date, default: Date.now }
});

const ScanHistorySchema = new Schema<IScanHistory>({
  userId: { type: String, required: true, index: true },
  qrType: { type: String, required: true },
  qrData: { type: String, required: true },
  decodedData: { type: Schema.Types.Mixed },
  imageUrl: { type: String },
  scannedAt: { type: Date, default: Date.now, index: true },
  metadata: {
    userAgent: String,
    ip: String,
    device: String
  }
});

const QRGenerationSchema = new Schema<IQRGeneration>({
  userId: { type: String, required: true, index: true },
  qrType: { type: String, required: true },
  data: { type: Schema.Types.Mixed, required: true },
  imageUrl: { type: String, required: true },
  generatedAt: { type: Date, default: Date.now, index: true }
});

const AnalyticsSchema = new Schema<IAnalytics>({
  date: { type: Date, required: true, unique: true, index: true },
  totalScans: { type: Number, default: 0 },
  totalGenerations: { type: Number, default: 0 },
  uniqueUsers: { type: Number, default: 0 },
  qrTypeBreakdown: { type: Map, of: Number, default: new Map() }
});

// ============================================
// MODELS
// ============================================

const User = mongoose.model<IUser>('User', UserSchema);
const ScanHistory = mongoose.model<IScanHistory>('ScanHistory', ScanHistorySchema);
const QRGeneration = mongoose.model<IQRGeneration>('QRGeneration', QRGenerationSchema);
const Analytics = mongoose.model<IAnalytics>('Analytics', AnalyticsSchema);

// ============================================
// EXPRESS APP SETUP
// ============================================

const app = express();
const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/scanqr';
const UPLOAD_DIR = path.join(process.cwd(), 'uploads');
const QR_OUTPUT_DIR = path.join(process.cwd(), 'qr-codes');

// Create upload directories if they don't exist
[UPLOAD_DIR, QR_OUTPUT_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

// ============================================
// MIDDLEWARE
// ============================================

app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Static files
app.use('/uploads', express.static(UPLOAD_DIR));
app.use('/qr-codes', express.static(QR_OUTPUT_DIR));

// Request logging middleware
app.use((req: Request, res: Response, next: NextFunction) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// User tracking middleware (creates or retrieves userId from header/session)
const userTrackingMiddleware = async (req: Request, res: Response, next: NextFunction) => {
  try {
    let userId = req.headers['x-user-id'] as string;
    
    if (!userId) {
      // Generate a unique user ID based on IP and User-Agent
      const identifier = `${req.ip}-${req.headers['user-agent']}`;
      userId = createHash('sha256').update(identifier).digest('hex').substring(0, 16);
    }
    
    // Update or create user
    await User.findOneAndUpdate(
      { userId },
      { 
        userId,
        lastActive: new Date()
      },
      { upsert: true, new: true }
    );
    
    (req as any).userId = userId;
    next();
  } catch (error) {
    console.error('User tracking error:', error);
    next();
  }
};

app.use(userTrackingMiddleware);

// Error handling middleware
const errorHandler = (err: any, req: Request, res: Response, next: NextFunction) => {
  console.error('Error:', err);
  
  res.status(err.status || 500).json({
    success: false,
    error: err.message || 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
};

// ============================================
// MULTER CONFIGURATION
// ============================================

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const fileFilter = (req: any, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/jpg', 'image/webp', 'image/gif'];
  
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only JPEG, PNG, WEBP, and GIF are allowed.'));
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  }
});

// ============================================
// HELPER FUNCTIONS
// ============================================

/**
 * Decode QR code from image file
 */
async function decodeQRFromImage(imagePath: string): Promise<string | null> {
  try {
    const fixedPath = path.resolve(imagePath);
    const image = await Jimp.read(fixedPath);

    // Ensure RGBA
    if (image.bitmap.data.length !== image.bitmap.width * image.bitmap.height * 4) {
      image.rgba(true);
    }

    // Do NOT resize — preserve QR fidelity
    image.grayscale().contrast(0.3);

    const { data, width, height } = image.bitmap;

    const code = jsQR(
      new Uint8ClampedArray(data),
      width,
      height,
      { inversionAttempts: "attemptBoth" }
    );

    return code?.data ?? null;
  } catch (err) {
    console.error("QR decode error:", err);
    return null;
  }
}



/**
 * Parse QR data based on type
 */
function parseQRData(data: string): { type: string; parsed: any } {
  // WiFi format: WIFI:T:WPA;S:MySSID;P:MyPassword;H:false;;
  if (data.startsWith('WIFI:')) {
    const matches = data.match(/WIFI:T:([^;]+);S:([^;]+);P:([^;]*);(?:H:([^;]*))?/);
    if (matches) {
      return {
        type: 'wifi',
        parsed: {
          encryption: matches[1],
          ssid: matches[2],
          password: matches[3] || '',
          hidden: matches[4] === 'true'
        }
      };
    }
  }
  
  // vCard format: BEGIN:VCARD...
  if (data.startsWith('BEGIN:VCARD')) {
    const vcard: any = {};
    const lines = data.split('\n');
    
    lines.forEach(line => {
      if (line.startsWith('FN:')) vcard.fullName = line.substring(3);
      if (line.startsWith('TEL:')) vcard.phone = line.substring(4);
      if (line.startsWith('EMAIL:')) vcard.email = line.substring(6);
      if (line.startsWith('ORG:')) vcard.organization = line.substring(4);
      if (line.startsWith('TITLE:')) vcard.title = line.substring(6);
      if (line.startsWith('URL:')) vcard.url = line.substring(4);
    });
    
    return { type: 'vcard', parsed: vcard };
  }
  
  // SMS format: smsto:+1234567890:Message
  if (data.startsWith('smsto:') || data.startsWith('SMSTO:')) {
    const parts = data.substring(6).split(':');
    return {
      type: 'sms',
      parsed: {
        number: parts[0],
        message: parts[1] || ''
      }
    };
  }
  
  // Tel format: tel:+1234567890
  if (data.startsWith('tel:') || data.startsWith('TEL:')) {
    return {
      type: 'call',
      parsed: { number: data.substring(4) }
    };
  }
  
  // Email format: mailto:email@example.com?subject=Subject&body=Body
  if (data.startsWith('mailto:')) {
    const url = new URL(data);
    return {
      type: 'mail',
      parsed: {
        email: url.pathname,
        subject: url.searchParams.get('subject') || '',
        body: url.searchParams.get('body') || ''
      }
    };
  }
  
  // Geo location: geo:37.786971,-122.399677
  if (data.startsWith('geo:')) {
    const coords = data.substring(4).split(',');
    return {
      type: 'location',
      parsed: {
        latitude: parseFloat(coords[0] ?? ''),
        longitude: parseFloat(coords[1] ?? '')
      }
    };
  }
  
  // Calendar event: BEGIN:VEVENT...
  if (data.startsWith('BEGIN:VEVENT')) {
    const event: any = {};
    const lines = data.split('\n');
    
    lines.forEach(line => {
      if (line.startsWith('SUMMARY:')) event.title = line.substring(8);
      if (line.startsWith('LOCATION:')) event.location = line.substring(9);
      if (line.startsWith('DESCRIPTION:')) event.description = line.substring(12);
      if (line.startsWith('DTSTART:')) event.startDate = line.substring(8);
      if (line.startsWith('DTEND:')) event.endDate = line.substring(6);
    });
    
    return { type: 'event', parsed: event };
  }
  
  // URL
  if (data.match(/^https?:\/\//)) {
    return {
      type: 'url',
      parsed: { url: data }
    };
  }
  
  // Default to text
  return {
    type: 'text',
    parsed: { text: data }
  };
}

/**
 * Generate QR code content based on type
 */
function generateQRContent(type: QRType, data: any): string {
  switch (type) {
    case 'wifi':
      const wifi = data as WiFiData;
      return `WIFI:T:${wifi.encryption};S:${wifi.ssid};P:${wifi.password};H:${wifi.hidden || false};;`;
    
    case 'vcard':
      const vcard = data as VCardData;
      return [
        'BEGIN:VCARD',
        'VERSION:3.0',
        `FN:${vcard.firstName} ${vcard.lastName}`,
        `N:${vcard.lastName};${vcard.firstName};;;`,
        vcard.organization ? `ORG:${vcard.organization}` : '',
        vcard.title ? `TITLE:${vcard.title}` : '',
        vcard.phone ? `TEL:${vcard.phone}` : '',
        vcard.email ? `EMAIL:${vcard.email}` : '',
        vcard.url ? `URL:${vcard.url}` : '',
        vcard.address ? `ADR:;;${vcard.address};;;;` : '',
        'END:VCARD'
      ].filter(Boolean).join('\n');
    
    case 'sms':
      return `smsto:${data.number}:${data.message || ''}`;
    
    case 'call':
      return `tel:${data.number}`;
    
    case 'mail':
      const params = new URLSearchParams();
      if (data.subject) params.append('subject', data.subject);
      if (data.body) params.append('body', data.body);
      return `mailto:${data.email}${params.toString() ? '?' + params.toString() : ''}`;
    
    case 'location':
      return `geo:${data.latitude},${data.longitude}`;
    
    case 'event':
      const event = data as EventData;
      return [
        'BEGIN:VEVENT',
        `SUMMARY:${event.title}`,
        event.location ? `LOCATION:${event.location}` : '',
        event.description ? `DESCRIPTION:${event.description}` : '',
        `DTSTART:${event.startDate}`,
        `DTEND:${event.endDate}`,
        'END:VEVENT'
      ].filter(Boolean).join('\n');
    
    case 'url':
      return data.url;
    
    case 'text':
    default:
      return data.text || data;
  }
}

/**
 * Update daily analytics
 */
async function updateAnalytics(type: 'scan' | 'generation', qrType: string, userId: string) {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const analytics = await Analytics.findOne({ date: today });
    
    if (analytics) {
      if (type === 'scan') {
        analytics.totalScans += 1;
      } else {
        analytics.totalGenerations += 1;
      }
      
      const currentCount = analytics.qrTypeBreakdown.get(qrType) || 0;
      analytics.qrTypeBreakdown.set(qrType, currentCount + 1);
      
      await analytics.save();
    } else {
      const breakdown = new Map<string, number>();
      breakdown.set(qrType, 1);
      
      await Analytics.create({
        date: today,
        totalScans: type === 'scan' ? 1 : 0,
        totalGenerations: type === 'generation' ? 1 : 0,
        uniqueUsers: 1,
        qrTypeBreakdown: breakdown
      });
    }
    
    // Update unique users count
    const uniqueUsers = await User.countDocuments({
      lastActive: { $gte: today }
    });
    
    await Analytics.updateOne(
      { date: today },
      { uniqueUsers }
    );
  } catch (error) {
    console.error('Analytics update error:', error);
  }
}

// ============================================
// API ROUTES
// ============================================

/**
 * Health check endpoint
 */
app.get('/api/health', (req: Request, res: Response) => {
  res.json({
    success: true,
    message: 'ScanQR Backend is running',
    timestamp: new Date().toISOString()
  });
});

/**
 * Upload and scan QR code from image
 * POST /api/scan/upload
 */
app.post('/api/scan/upload', upload.single('qrImage'), async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'No image file uploaded'
      });
    }

    console.log(req.file);
    
    const userId = (req as any).userId;
    const imagePath = req.file.path;
    
    // Decode QR code
    const qrData = await decodeQRFromImage(imagePath);
    
    if (!qrData) {
      // Clean up uploaded file
      fs.unlinkSync(imagePath);
      
      return res.status(400).json({
        success: false,
        error: 'No QR code found in the image'
      });
    }
    
    // Parse QR data
    const { type, parsed } = parseQRData(qrData);
    
    // Save to scan history
    const scanRecord = await ScanHistory.create({
      userId,
      qrType: type,
      qrData,
      decodedData: parsed,
      imageUrl: `/uploads/${req.file.filename}`,
      metadata: {
        userAgent: req.headers['user-agent'],
        ip: req.ip,
        device: req.headers['user-agent']?.includes('Mobile') ? 'mobile' : 'desktop'
      }
    });
    
    // Update analytics
    await updateAnalytics('scan', type, userId);
    
    res.json({
      success: true,
      data: {
        id: scanRecord._id,
        type,
        rawData: qrData,
        parsed,
        scannedAt: scanRecord.scannedAt
      }
    });
    
  } catch (error) {
    next(error);
  }
});

/**
 * Scan QR code from base64 image (for webcam captures)
 * POST /api/scan/base64
 */
app.post('/api/scan/base64', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { image } = req.body;
    
    if (!image) {
      return res.status(400).json({
        success: false,
        error: 'No image data provided'
      });
    }
    
    const userId = (req as any).userId;
    
    // Remove data URL prefix if present
    const base64Data = image.replace(/^data:image\/\w+;base64,/, '');
    const buffer = Buffer.from(base64Data, 'base64');
    
    // Save temporary file
    const tempPath = path.join(UPLOAD_DIR, `temp-${Date.now()}.png`);
    fs.writeFileSync(tempPath, buffer);
    
    // Decode QR code
    const qrData = await decodeQRFromImage(tempPath);
    
    // Clean up temp file
    fs.unlinkSync(tempPath);
    
    if (!qrData) {
      return res.status(400).json({
        success: false,
        error: 'No QR code found in the image'
      });
    }
    
    // Parse QR data
    const { type, parsed } = parseQRData(qrData);
    
    // Save to scan history (without image URL for privacy)
    const scanRecord = await ScanHistory.create({
      userId,
      qrType: type,
      qrData,
      decodedData: parsed,
      metadata: {
        userAgent: req.headers['user-agent'],
        ip: req.ip,
        device: req.headers['user-agent']?.includes('Mobile') ? 'mobile' : 'desktop'
      }
    });
    
    // Update analytics
    await updateAnalytics('scan', type, userId);
    
    res.json({
      success: true,
      data: {
        id: scanRecord._id,
        type,
        rawData: qrData,
        parsed,
        scannedAt: scanRecord.scannedAt
      }
    });
    
  } catch (error) {
    next(error);
  }
});

/**
 * Generate QR code
 * POST /api/generate
 */
app.post('/api/generate', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { type, data, options = {} } = req.body;
    
    if (!type || !data) {
      return res.status(400).json({
        success: false,
        error: 'Type and data are required'
      });
    }
    
    const userId = (req as any).userId;
    
    // Generate QR content
    const qrContent = generateQRContent(type as QRType, data);
    
    // Generate QR code image
    const filename = `qr-${Date.now()}-${Math.random().toString(36).substring(7)}.png`;
    const outputPath = path.join(QR_OUTPUT_DIR, filename);
    
    const qrOptions = {
      errorCorrectionLevel: options.errorCorrectionLevel || 'M',
      type: 'png' as const,
      quality: options.quality || 0.92,
      margin: options.margin || 1,
      width: options.width || 300,
      color: {
        dark: options.darkColor || '#000000',
        light: options.lightColor || '#FFFFFF'
      }
    };
    
    await QRCode.toFile(outputPath, qrContent, qrOptions);
    
    // Save to database
    const qrRecord = await QRGeneration.create({
      userId,
      qrType: type,
      data,
      imageUrl: `http://localhost:${PORT}/qr-codes/${filename}`
    });
    
    // Update analytics
    await updateAnalytics('generation', type, userId);
    
    res.json({
      success: true,
      data: {
        id: qrRecord._id,
        type,
        imageUrl: qrRecord.imageUrl,
        content: qrContent,
        generatedAt: qrRecord.generatedAt
      }
    });
    
  } catch (error) {
    next(error);
  }
});

/**
 * Get scan history for user
 * GET /api/history/scans?limit=100&page=1
 */
app.get('/api/history/scans', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = (req as any).userId;
    const limit = parseInt(req.query.limit as string) || 100;
    const page = parseInt(req.query.page as string) || 1;
    const skip = (page - 1) * limit;
    
    const scans = await ScanHistory.find({ userId })
      .sort({ scannedAt: -1 })
      .limit(limit)
      .skip(skip)
      .select('-__v');
    
    const total = await ScanHistory.countDocuments({ userId });
    
    res.json({
      success: true,
      data: {
        scans,
        pagination: {
          total,
          page,
          limit,
          pages: Math.ceil(total / limit)
        }
      }
    });
    
  } catch (error) {
    next(error);
  }
});

/**
 * Get generation history for user
 * GET /api/history/generations?limit=100&page=1
 */
app.get('/api/history/generations', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = (req as any).userId;
    const limit = parseInt(req.query.limit as string) || 100;
    const page = parseInt(req.query.page as string) || 1;
    const skip = (page - 1) * limit;
    
    const generations = await QRGeneration.find({ userId })
      .sort({ generatedAt: -1 })
      .limit(limit)
      .skip(skip)
      .select('-__v');
    
    const total = await QRGeneration.countDocuments({ userId });
    
    res.json({
      success: true,
      data: {
        generations,
        pagination: {
          total,
          page,
          limit,
          pages: Math.ceil(total / limit)
        }
      }
    });
    
  } catch (error) {
    next(error);
  }
});

/**
 * Delete scan history item
 * DELETE /api/history/scans/:id
 */
app.delete('/api/history/scans/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = (req as any).userId;
    const { id } = req.params;
    
    const scan = await ScanHistory.findOneAndDelete({
      _id: id,
      userId
    });
    
    if (!scan) {
      return res.status(404).json({
        success: false,
        error: 'Scan not found'
      });
    }
    
    // Delete associated image file if exists
    if (scan.imageUrl) {
      const imagePath = path.join(process.cwd(), scan.imageUrl);
      if (fs.existsSync(imagePath)) {
        fs.unlinkSync(imagePath);
      }
    }
    
    res.json({
      success: true,
      message: 'Scan deleted successfully'
    });
    
  } catch (error) {
    next(error);
  }
});

/**
 * Delete generation history item
 * DELETE /api/history/generations/:id
 */
app.delete('/api/history/generations/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = (req as any).userId;
    const { id } = req.params;
    
    const generation = await QRGeneration.findOneAndDelete({
      _id: id,
      userId
    });
    
    if (!generation) {
      return res.status(404).json({
        success: false,
        error: 'Generation not found'
      });
    }
    
    // Delete associated QR image
    const imagePath = path.join(process.cwd(), generation.imageUrl);
    if (fs.existsSync(imagePath)) {
      fs.unlinkSync(imagePath);
    }
    
    res.json({
      success: true,
      message: 'Generation deleted successfully'
    });
    
  } catch (error) {
    next(error);
  }
});

/**
 * Clear all scan history for user
 * DELETE /api/history/scans
 */
app.delete('/api/history/scans', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = (req as any).userId;
    
    // Get all scans to delete associated files
    const scans = await ScanHistory.find({ userId });
    
    // Delete files
    scans.forEach(scan => {
      if (scan.imageUrl) {
        const imagePath = path.join(process.cwd(), scan.imageUrl);
        if (fs.existsSync(imagePath)) {
          fs.unlinkSync(imagePath);
        }
      }
    });
    
    // Delete records
    const result = await ScanHistory.deleteMany({ userId });
    
    res.json({
      success: true,
      message: `Deleted ${result.deletedCount} scans`
    });
    
  } catch (error) {
    next(error);
  }
});

/**
 * Get user statistics
 * GET /api/stats/user
 */
app.get('/api/stats/user', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = (req as any).userId;
    
    const totalScans = await ScanHistory.countDocuments({ userId });
    const totalGenerations = await QRGeneration.countDocuments({ userId });
    
    // Get breakdown by type
    const scanTypeBreakdown = await ScanHistory.aggregate([
      { $match: { userId } },
      { $group: { _id: '$qrType', count: { $sum: 1 } } }
    ]);
    
    const generationTypeBreakdown = await QRGeneration.aggregate([
      { $match: { userId } },
      { $group: { _id: '$qrType', count: { $sum: 1 } } }
    ]);
    
    // Get recent activity
    const recentScans = await ScanHistory.find({ userId })
      .sort({ scannedAt: -1 })
      .limit(5)
      .select('qrType scannedAt');
    
    const recentGenerations = await QRGeneration.find({ userId })
      .sort({ generatedAt: -1 })
      .limit(5)
      .select('qrType generatedAt');
    
    res.json({
      success: true,
      data: {
        totalScans,
        totalGenerations,
        scanTypeBreakdown: scanTypeBreakdown.reduce((acc, item) => {
          acc[item._id] = item.count;
          return acc;
        }, {} as Record<string, number>),
        generationTypeBreakdown: generationTypeBreakdown.reduce((acc, item) => {
          acc[item._id] = item.count;
          return acc;
        }, {} as Record<string, number>),
        recentActivity: {
          scans: recentScans,
          generations: recentGenerations
        }
      }
    });
    
  } catch (error) {
    next(error);
  }
});

/**
 * Get global analytics (admin endpoint - should be protected in production)
 * GET /api/stats/global?days=30
 */
app.get('/api/stats/global', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const days = parseInt(req.query.days as string) || 30;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);
    startDate.setHours(0, 0, 0, 0);
    
    const analytics = await Analytics.find({
      date: { $gte: startDate }
    }).sort({ date: 1 });
    
    const totalStats = analytics.reduce((acc, day) => {
      acc.totalScans += day.totalScans;
      acc.totalGenerations += day.totalGenerations;
      acc.maxUniqueUsers = Math.max(acc.maxUniqueUsers, day.uniqueUsers);
      return acc;
    }, { totalScans: 0, totalGenerations: 0, maxUniqueUsers: 0 });
    
    res.json({
      success: true,
      data: {
        period: {
          days,
          startDate,
          endDate: new Date()
        },
        summary: totalStats,
        daily: analytics
      }
    });
    
  } catch (error) {
    next(error);
  }
});

/**
 * Export user data (GDPR compliance)
 * GET /api/export
 */
app.get('/api/export', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = (req as any).userId;
    
    const user = await User.findOne({ userId });
    const scans = await ScanHistory.find({ userId });
    const generations = await QRGeneration.find({ userId });
    
    const exportData = {
      user,
      scans,
      generations,
      exportedAt: new Date()
    };
    
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="scanqr-data-${userId}.json"`);
    res.json(exportData);
    
  } catch (error) {
    next(error);
  }
});

/**
 * Search QR types information
 * GET /api/qr-types
 */
app.get('/api/qr-types', (req: Request, res: Response) => {
  const qrTypes = [
    {
      type: 'url',
      name: 'URL',
      description: 'Link to any webpage',
      example: { url: 'https://example.com' }
    },
    {
      type: 'text',
      name: 'Text',
      description: 'Represents plain text',
      example: { text: 'Hello World' }
    },
    {
      type: 'location',
      name: 'Location',
      description: 'Geographical position (Google Maps)',
      example: { latitude: 37.786971, longitude: -122.399677 }
    },
    {
      type: 'wifi',
      name: 'WiFi',
      description: 'Connects to a wireless network',
      example: { ssid: 'MyNetwork', password: 'password123', encryption: 'WPA' }
    },
    {
      type: 'vcard',
      name: 'vCard',
      description: 'Digital business card',
      example: { 
        firstName: 'John', 
        lastName: 'Doe', 
        phone: '+1234567890',
        email: 'john@example.com',
        organization: 'Example Corp'
      }
    },
    {
      type: 'sms',
      name: 'SMS',
      description: 'Send SMS on a smartphone',
      example: { number: '+1234567890', message: 'Hello!' }
    },
    {
      type: 'call',
      name: 'Call',
      description: 'Start a phone call',
      example: { number: '+1234567890' }
    },
    {
      type: 'event',
      name: 'Event',
      description: 'Calendar entry for any event',
      example: { 
        title: 'Meeting',
        location: 'Office',
        startDate: '20260301T100000',
        endDate: '20260301T110000'
      }
    },
    {
      type: 'mail',
      name: 'Email',
      description: 'Initiate email draft to a recipient',
      example: { 
        email: 'contact@example.com',
        subject: 'Hello',
        body: 'Message body'
      }
    }
  ];
  
  res.json({
    success: true,
    data: qrTypes
  });
});

// Error handler (must be last)
app.use(errorHandler);

// ============================================
// DATABASE CONNECTION & SERVER START
// ============================================

async function startServer() {
  try {
    // Connect to MongoDB
    await mongoose.connect(MONGO_URI);
    console.log('✅ Connected to MongoDB');
    
    // Start server
    app.listen(PORT, () => {
      console.log(`🚀 ScanQR Backend running on port ${PORT}`);
      console.log(`📁 Upload directory: ${UPLOAD_DIR}`);
      console.log(`📁 QR output directory: ${QR_OUTPUT_DIR}`);
      console.log(`🌐 Health check: http://localhost:${PORT}/api/health`);
    });
    
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

// Handle graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, closing server...');
  await mongoose.connection.close();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, closing server...');
  await mongoose.connection.close();
  process.exit(0);
});

// Start the server
startServer();

export default app;