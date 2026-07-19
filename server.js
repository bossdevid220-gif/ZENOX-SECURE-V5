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

app.set('trust proxy', 1);

mongoose.connect(process.env.MONGODB_URI)
.then(() => {
    console.log('SERVER CONNECTED TO DATABASE');
})
.catch(err => console.log('DATABASE ERROR:', err.message));

const UserSchema = new mongoose.Schema({
    deviceId: { type: String, unique: true, required: true, trim: true },
    accessKey: { type: String, required: true },
    role: { type: String, default: 'user', enum: ['user', 'admin'] },
    expiresAt: { type: Date, required: true },
    isActive: { type: Boolean, default: true }
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);

app.use(helmet({
    contentSecurityPolicy: false
}));

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: 'TOO MANY ATTEMPTS. PLEASE TRY AGAIN LATER.'
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: process.env.SESSION_SECRET || 'ZENOX_SUPER_SECRET_KEY_2026',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI,
        ttl: 24 * 60 * 60
    }),
    cookie: {
        secure: true,
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000
    }
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.redirect('/ZENOX-GATEWAY-LOGIN');
    }
    next();
}

function requireAdmin(req, res, next) {
    if (req.session.role !== 'admin') {
        return res.status(403).send('ACCESS DENIED');
    }
    next();
}

app.get('/', (req, res) => {
    res.redirect('/ZENOX-GATEWAY-LOGIN');
});

app.get('/ZENOX-GATEWAY-LOGIN', (req, res) => {
    res.render('login', { error: null });
});

app.post('/ZENOX-GATEWAY-LOGIN', authLimiter, async (req, res) => {
    const { deviceId, password } = req.body;
    
    if (!deviceId || deviceId.includes('GENERATING')) {
        return res.render('login', { error: 'DEVICE ID ERROR. PLEASE REFRESH.' });
    }

    try {
        const masterPassword = process.env.ADMIN_PASSWORD || 'ZENOX@2026#SECURE$';
        
        if (password === masterPassword) {
            let user = await User.findOne({ deviceId });
            
            if (!user) {
                let expirationDate = new Date();
                expirationDate.setFullYear(expirationDate.getFullYear() + 10);
                
                const hashedPassword = await bcrypt.hash(password, 12);
                user = new User({
                    deviceId: deviceId,
                    accessKey: hashedPassword,
                    role: 'admin',
                    expiresAt: expirationDate,
                    isActive: true
                });
                await user.save();
            }

            req.session.userId = user._id;
            req.session.role = user.role;
            req.session.deviceId = user.deviceId;

            return res.redirect('/ZENOX-PORTAL-CORE-X92');
        } else {
            const user = await User.findOne({ deviceId });
            if (!user) {
                return res.render('login', { error: 'UNAUTHORIZED DEVICE ID.' });
            }
            if (!user.isActive) {
                return res.render('login', { error: 'ACCESS HAS BEEN DEACTIVATED.' });
            }
            if (new Date() > user.expiresAt) {
                return res.render('login', { error: 'ACCESS LICENSE HAS EXPIRED.' });
            }
            const isKeyValid = await bcrypt.compare(password, user.accessKey);
            if (!isKeyValid) {
                return res.render('login', { error: 'INVALID ACCESS LICENSE KEY.' });
            }
            req.session.userId = user._id;
            req.session.role = user.role;
            req.session.deviceId = user.deviceId;
            return res.redirect('/ZENOX-PORTAL-CORE-X92');
        }
    } catch (error) {
        res.render('login', { error: 'SERVER SAFETY ERROR.' });
    }
});


app.get('/ZENOX-PORTAL-CORE-X92', requireAuth, (req, res) => {
    res.render('dashboard', { deviceId: req.session.deviceId, role: req.session.role });
});

app.get('/ZENOX-MAIN-TERMINAL-ROOT', requireAuth, requireAdmin, async (req, res) => {
    try {
        const allUsers = await User.find({});
        res.render('admin', { deviceId: req.session.deviceId, users: allUsers, success: null, generatedKey: null });
    } catch (error) {
        res.status(500).send('SERVER ERROR');
    }
});

app.post('/ZENOX-GENERATE-ACCESS', requireAuth, requireAdmin, async (req, res) => {
    const { targetDeviceId, durationType, durationValue, targetRole } = req.body;
    try {
        const rawKey = 'ZENOX-KEY-' + crypto.randomBytes(8).toString('hex').toUpperCase();
        const hashedKey = await bcrypt.hash(rawKey, 12);
        
        let expirationDate = new Date();
        const value = parseInt(durationValue);
        
        if (durationType === 'MINUTES') expirationDate.setMinutes(expirationDate.getMinutes() + value);
        else if (durationType === 'HOURS') expirationDate.setHours(expirationDate.getHours() + value);
        else if (durationType === 'DAYS') expirationDate.setDate(expirationDate.getDate() + value);

        await User.findOneAndUpdate(
            { deviceId: targetDeviceId },
            { 
                accessKey: hashedKey, 
                role: targetRole, 
                expiresAt: expirationDate,
                isActive: true
            },
            { upsert: true, new: true }
        );

        const allUsers = await User.find({});
        res.render('admin', { 
            deviceId: req.session.deviceId, 
            users: allUsers, 
            success: 'ACCESS KEY GENERATED SUCCESSFULLY FOR THIS DEVICE',
            generatedKey: rawKey 
        });
    } catch (error) {
        res.status(500).send('GENERATION ERROR');
    }
});

app.post('/ZENOX-REVOKE-ACCESS', requireAuth, requireAdmin, async (req, res) => {
    const { targetDeviceId } = req.body;
    try {
        await User.findOneAndUpdate({ deviceId: targetDeviceId }, { isActive: false });
        res.redirect('/ZENOX-MAIN-TERMINAL-ROOT');
    } catch (error) {
        res.status(500).send('REVOCATION ERROR');
    }
});

app.get('/ZENOX-TERMINATE', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/ZENOX-GATEWAY-LOGIN');
    });
});

app.use((req, res) => {
    res.status(404).send('PAGE NOT FOUND');
});

app.listen(PORT, () => {
    console.log(`SERVER RUNNING ON PORT ${PORT}`);
});
