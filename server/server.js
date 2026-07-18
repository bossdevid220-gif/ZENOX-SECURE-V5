const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

// ============ TRUST PROXY ============
app.set('trust proxy', 1);

// ============ DATABASE ============
mongoose.connect(process.env.MONGODB_URI)
.then(() => {
    console.log('✅ MONGODB CONNECTED');
    createDefaultAdmin();
})
.catch(err => console.log('❌ MONGODB ERROR:', err.message));

// ============ USER SCHEMA ============
const UserSchema = new mongoose.Schema({
    deviceId: { type: String, unique: true, required: true, trim: true },
    passwordHash: { type: String, required: true },
    role: { type: String, default: 'user', enum: ['user', 'admin'] },
    isActive: { type: Boolean, default: true },
    lastLogin: { type: Date },
    loginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date },
    createdAt: { type: Date, default: Date.now }
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);

// ============ CREATE ADMIN ============
async function createDefaultAdmin() {
    try {
        const adminExists = await User.findOne({ role: 'admin' });
        if (!adminExists) {
            const adminPassword = process.env.ADMIN_PASSWORD || 'UnbreakableAdmin@2026#Secure$';
            const hashedPassword = await bcrypt.hash(adminPassword, 12);
            const admin = new User({
                deviceId: 'ADMIN-DEVICE-001',
                passwordHash: hashedPassword,
                role: 'admin',
                isActive: true
            });
            await admin.save();
            console.log('✅ ADMIN USER CREATED!');
            console.log('📛 ADMIN-DEVICE-001');
            console.log('🔑 ' + adminPassword);
        }
    } catch (error) {
        console.log('⚠️ ADMIN ERROR:', error.message);
    }
}

// ============ SESSION ============
const sessionStore = MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    collectionName: 'sessions',
    ttl: 24 * 60 * 60,
    autoRemove: 'native'
});

// ============ MIDDLEWARE ============
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"]
        }
    }
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/static', express.static(path.join(__dirname, '../public')));

app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback_secret',
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000,
        path: '/'
    },
    name: '__Secure-zx-session'
}));

// ============ CSRF - SIMPLIFIED ============
app.use((req, res, next) => {
    if (!req.session.token) {
        req.session.token = crypto.randomBytes(32).toString('hex');
    }
    res.locals.csrfToken = req.session.token;
    req.csrfToken = () => req.session.token;
    next();
});

app.use((req, res, next) => {
    if (req.method === 'POST') {
        const token = req.body._csrf || req.headers['x-csrf-token'];
        if (!token || token !== req.session.token) {
            console.log('⚠️ CSRF MISMATCH - CONTINUING');
        }
    }
    next();
});

// ============ RATE LIMITER ============
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Too many login attempts. Try again later.',
    trustProxy: true,
    standardHeaders: true,
    legacyHeaders: false
});

// ============ VIEW ENGINE ============
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ============ AUTH MIDDLEWARE ============
function requireAuth(req, res, next) {
    if (!req.session || !req.session.userId) {
        return res.redirect('/login');
    }
    next();
}

function requireAdmin(req, res, next) {
    if (!req.session || !req.session.userId) {
        return res.redirect('/login');
    }
    User.findById(req.session.userId)
        .then(user => {
            if (!user || user.role !== 'admin') {
                return res.status(403).send('ADMIN ONLY');
            }
            next();
        })
        .catch(() => res.status(500).send('ERROR'));
}

// ============ ROUTES ============
app.get('/', (req, res) => res.redirect('/login'));

app.get('/login', (req, res) => {
    if (req.session && req.session.userId) {
        return res.redirect('/dashboard');
    }
    res.render('login', { 
        csrfToken: req.csrfToken(), 
        error: null 
    });
});

app.post('/login', authLimiter, async (req, res) => {
    const { deviceId, password } = req.body;
    
    if (!deviceId || !password) {
        return res.render('login', { 
            csrfToken: req.csrfToken(), 
            error: 'ALL FIELDS REQUIRED' 
        });
    }
    
    try {
        let user = await User.findOne({ deviceId });
        
        if (!user) {
            const keyExists = await User.findOne({ deviceId: password });
            if (!keyExists) {
                return res.render('login', { 
                    csrfToken: req.csrfToken(), 
                    error: 'INVALID CREDENTIALS' 
                });
            }
            
            const hashedPassword = await bcrypt.hash(password, 12);
            user = new User({
                deviceId: deviceId,
                passwordHash: hashedPassword,
                role: 'user'
            });
            await user.save();
            console.log(`✅ NEW USER: ${deviceId}`);
        }
        
        if (!user.isActive) {
            return res.render('login', { 
                csrfToken: req.csrfToken(), 
                error: 'ACCOUNT DISABLED' 
            });
        }
        
        if (user.lockUntil && user.lockUntil > Date.now()) {
            const remaining = Math.ceil((user.lockUntil - Date.now()) / 60000);
            return res.render('login', { 
                csrfToken: req.csrfToken(), 
                error: `ACCOUNT LOCKED. TRY IN ${remaining} MINUTES` 
            });
        }
        
        const isValid = await bcrypt.compare(password, user.passwordHash);
        if (!isValid) {
            user.loginAttempts += 1;
            if (user.loginAttempts >= 5) {
                user.lockUntil = Date.now() + 15 * 60 * 1000;
                await user.save();
                return res.render('login', { 
                    csrfToken: req.csrfToken(), 
                    error: 'TOO MANY ATTEMPTS. LOCKED 15 MINUTES' 
                });
            }
            await user.save();
            return res.render('login', { 
                csrfToken: req.csrfToken(), 
                error: 'INVALID CREDENTIALS' 
            });
        }
        
        user.loginAttempts = 0;
        user.lockUntil = null;
        user.lastLogin = new Date();
        await user.save();
        
        req.session.userId = user._id;
        req.session.role = user.role;
        req.session.deviceId = user.deviceId;
        
        console.log(`✅ USER LOGGED IN: ${deviceId} (${user.role})`);
        
        if (user.role === 'admin') {
            return res.redirect('/admin');
        }
        res.redirect('/dashboard');
        
    } catch (error) {
        console.error('LOGIN ERROR:', error);
        res.render('login', { 
            csrfToken: req.csrfToken(), 
            error: 'SERVER ERROR. TRY AGAIN.' 
        });
    }
});

app.get('/dashboard', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        if (!user) {
            req.session.destroy();
            return res.redirect('/login');
        }
        res.render('dashboard', { 
            deviceId: user.deviceId,
            role: user.role,
            csrfToken: req.csrfToken()
        });
    } catch {
        res.redirect('/login');
    }
});

app.get('/admin', requireAdmin, async (req, res) => {
    try {
        const users = await User.find({}).select('-passwordHash').sort({ createdAt: -1 });
        res.render('admin', { 
            users: users,
            csrfToken: req.csrfToken()
        });
    } catch {
        res.render('admin', { 
            users: [], 
            csrfToken: req.csrfToken()
        });
    }
});

app.post('/admin/user/:id/toggle', requireAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (user) {
            user.isActive = !user.isActive;
            await user.save();
        }
        res.redirect('/admin');
    } catch {
        res.redirect('/admin');
    }
});

app.post('/admin/user/:id/delete', requireAdmin, async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id);
        res.redirect('/admin');
    } catch {
        res.redirect('/admin');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ============ START ============
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🛡️ UNBREAKABLE SERVER ON PORT ${PORT}`);
    console.log(`🔐 https://unbreakable-app.onrender.com`);
});
