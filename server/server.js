const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

// ============ DATABASE CONNECTION ============
console.log('🔐 Connecting to MongoDB...');

mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => {
    console.log('✅ MongoDB Connected Successfully!');
    createDefaultAdmin();
})
.catch(err => {
    console.log('❌ MongoDB Connection Error:', err.message);
    console.log('⚠️ Please check your MONGODB_URI in .env file');
});

// ============ USER SCHEMA ============
const UserSchema = new mongoose.Schema({
    deviceId: { 
        type: String, 
        unique: true, 
        required: true,
        trim: true,
        minlength: 3
    },
    passwordHash: { 
        type: String, 
        required: true 
    },
    role: { 
        type: String, 
        default: 'user',
        enum: ['user', 'admin']
    },
    isActive: { 
        type: Boolean, 
        default: true 
    },
    lastLogin: { 
        type: Date 
    },
    loginAttempts: { 
        type: Number, 
        default: 0 
    },
    lockUntil: { 
        type: Date 
    },
    sessionId: { 
        type: String 
    },
    createdAt: { 
        type: Date, 
        default: Date.now 
    }
}, {
    timestamps: true
});

const User = mongoose.model('User', UserSchema);

// ============ CREATE DEFAULT ADMIN USER ============
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
            console.log('✅ Default admin user created!');
            console.log('📛 Admin Device ID: ADMIN-DEVICE-001');
            console.log('🔑 Admin Password: ' + adminPassword);
        }
    } catch (error) {
        console.log('⚠️ Admin user creation error:', error.message);
    }
}

// ============ SESSION STORE ============
const sessionStore = MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    collectionName: 'sessions',
    ttl: 24 * 60 * 60,
    autoRemove: 'native'
});

// ============ MIDDLEWARE ============

// Helmet - Security Headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"]
        }
    },
    hsts: { 
        maxAge: 31536000, 
        includeSubDomains: true, 
        preload: true 
    },
    noSniff: true,
    referrerPolicy: { 
        policy: 'same-origin' 
    },
    frameguard: { 
        action: 'deny' 
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: { 
        policy: 'same-origin' 
    },
    crossOriginResourcePolicy: { 
        policy: 'same-origin' 
    }
}));

// Body Parser
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Static Files
app.use('/static', express.static(path.join(__dirname, '../public')));

// ============ SESSION (HTTP-Only Cookies) ============
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback_secret_change_this',
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

// ============ CSRF PROTECTION ============
const csrfProtection = csrf({ 
    cookie: false,
    ignoreMethods: ['GET', 'HEAD', 'OPTIONS']
});
app.use(csrfProtection);
// ============ RATE LIMITING ============
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests. Please try again later.',
    standardHeaders: true,
    legacyHeaders: false
});
app.use('/api', limiter);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Too many login attempts. Please try again later.',
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
                return res.status(403).send('⛔ Access Denied. Admin only.');
            }
            next();
        })
        .catch(() => res.status(500).send('Server Error'));
}

// ============ ROUTES ============

// ---------- ROOT (/) REDIRECT TO LOGIN ----------
app.get('/', (req, res) => {
    res.redirect('/login');
});

// ---------- LOGIN PAGE ----------
app.get('/login', (req, res) => {
    if (req.session && req.session.userId) {
        return res.redirect('/dashboard');
    }
    res.render('login', { 
        csrfToken: req.csrfToken(), 
        error: null 
    });
});

// ---------- LOGIN POST ----------
app.post('/login', authLimiter, async (req, res) => {
    const { deviceId, password } = req.body;
    
    if (!deviceId || !password) {
        return res.render('login', { 
            csrfToken: req.csrfToken(), 
            error: 'All fields are required' 
        });
    }
    
    try {
        let user = await User.findOne({ deviceId });
        
        if (!user) {
            // Check if access key exists
            const keyExists = await User.findOne({ deviceId: password });
            if (!keyExists) {
                return res.render('login', { 
                    csrfToken: req.csrfToken(), 
                    error: 'Invalid credentials. Please check your access key.' 
                });
            }
            
            // Create new user
            const hashedPassword = await bcrypt.hash(password, 12);
            user = new User({
                deviceId: deviceId,
                passwordHash: hashedPassword,
                role: 'user'
            });
            await user.save();
            console.log(`✅ New user registered: ${deviceId}`);
        }
        
        // Check if account is active
        if (!user.isActive) {
            return res.render('login', { 
                csrfToken: req.csrfToken(), 
                error: 'Account is disabled. Contact admin.' 
            });
        }
        
        // Check lock
        if (user.lockUntil && user.lockUntil > Date.now()) {
            const remaining = Math.ceil((user.lockUntil - Date.now()) / 60000);
            return res.render('login', { 
                csrfToken: req.csrfToken(), 
                error: `Account locked. Try again in ${remaining} minutes.` 
            });
        }
        
        // Verify password
        const isValid = await bcrypt.compare(password, user.passwordHash);
        if (!isValid) {
            user.loginAttempts += 1;
            if (user.loginAttempts >= 5) {
                user.lockUntil = Date.now() + 15 * 60 * 1000;
                await user.save();
                return res.render('login', { 
                    csrfToken: req.csrfToken(), 
                    error: 'Too many attempts. Account locked for 15 minutes.' 
                });
            }
            await user.save();
            return res.render('login', { 
                csrfToken: req.csrfToken(), 
                error: 'Invalid credentials. Please try again.' 
            });
        }
        
        // Reset attempts
        user.loginAttempts = 0;
        user.lockUntil = null;
        user.lastLogin = new Date();
        await user.save();
        
        // Create session
        req.session.userId = user._id;
        req.session.role = user.role;
        req.session.deviceId = user.deviceId;
        
        console.log(`✅ User logged in: ${deviceId} (${user.role})`);
        
        // Redirect based on role
        if (user.role === 'admin') {
            return res.redirect('/admin');
        }
        res.redirect('/dashboard');
        
    } catch (error) {
        console.error('Login error:', error);
        res.render('login', { 
            csrfToken: req.csrfToken(), 
            error: 'Server error. Please try again.' 
        });
    }
});

// ---------- DASHBOARD ----------
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
    } catch (error) {
        console.error('Dashboard error:', error);
        res.redirect('/login');
    }
});

// ---------- ADMIN ----------
app.get('/admin', requireAdmin, async (req, res) => {
    try {
        const users = await User.find({}).select('-passwordHash').sort({ createdAt: -1 });
        res.render('admin', { 
            users: users,
            csrfToken: req.csrfToken()
        });
    } catch (error) {
        console.error('Admin error:', error);
        res.render('admin', { 
            users: [], 
            csrfToken: req.csrfToken()
        });
    }
});

// ---------- ADMIN: TOGGLE USER ----------
app.post('/admin/user/:id/toggle', requireAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (user) {
            user.isActive = !user.isActive;
            await user.save();
            console.log(`✅ User ${user.deviceId} ${user.isActive ? 'enabled' : 'disabled'}`);
        }
        res.redirect('/admin');
    } catch (error) {
        console.error('Toggle error:', error);
        res.redirect('/admin');
    }
});

// ---------- ADMIN: DELETE USER ----------
app.post('/admin/user/:id/delete', requireAdmin, async (req, res) => {
    try {
        const user = await User.findByIdAndDelete(req.params.id);
        if (user) {
            console.log(`✅ User deleted: ${user.deviceId}`);
        }
        res.redirect('/admin');
    } catch (error) {
        console.error('Delete error:', error);
        res.redirect('/admin');
    }
});

// ---------- LOGOUT ----------
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout error:', err);
        }
        res.redirect('/login');
    });
});

// ---------- HEALTH CHECK ----------
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// ============ ERROR HANDLING ============
app.use((err, req, res, next) => {
    console.error('Server Error:', err);
    
    if (err.code === 'EBADCSRFTOKEN') {
        return res.render('login', { 
            csrfToken: req.csrfToken ? req.csrfToken() : '', 
            error: 'Session expired. Please refresh and try again.' 
        });
    }
    
    res.status(500).send('Something went wrong. Please try again later.');
});

// ============ 404 HANDLER ============
app.use((req, res) => {
    res.status(404).send('Page not found');
});

// ============ START SERVER ============
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🛡️ Unbreakable Server running on port ${PORT}`);
    console.log(`🔐 https://unbreakable-app.onrender.com`);
    console.log(`📱 Health: https://unbreakable-app.onrender.com/health`);
});

// ============ GRACEFUL SHUTDOWN ============
process.on('SIGTERM', async () => {
    console.log('SIGTERM received. Shutting down gracefully...');
    await mongoose.disconnect();
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('SIGINT received. Shutting down gracefully...');
    await mongoose.disconnect();
    process.exit(0);
});
