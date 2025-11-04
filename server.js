const path = require('path');
const express = require('express');
const session = require('express-session');
const flash = require('connect-flash');
const methodOverride = require('method-override');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const multer = require('multer');
const fs = require('fs');
let PDFDocument = null;
try { PDFDocument = require('pdfkit'); } catch (e) { PDFDocument = null; }
let twilioClient = null;
try {
    if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN) {
        twilioClient = require('twilio')(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
    }
} catch (e) {}
let puppeteer = null;
try { puppeteer = require('puppeteer'); } catch (e) { puppeteer = null; }
let XLSX = null;
try { XLSX = require('xlsx'); } catch (e) { XLSX = null; }

async function renderBillPng(app, bill, items, settings, outPath) {
    if (!puppeteer) throw new Error('Puppeteer not available');
    const html = await new Promise((resolve, reject) => {
        app.render('share_bill', { bill, items, settings }, (err, str) => err ? reject(err) : resolve(str));
    });
    const browser = await puppeteer.launch({ args: ['--no-sandbox','--disable-setuid-sandbox'] });
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'networkidle0' });
    await page.setViewport({ width: 900, height: 1200, deviceScaleFactor: 2 });
    await page.screenshot({ path: outPath, type: 'png', fullPage: true });
    await browser.close();
}

async function sendWhatsappMedia(toE164, body, mediaUrl) {
    if (!twilioClient || !process.env.WHATSAPP_FROM) throw new Error('Twilio not configured');
    return await twilioClient.messages.create({
        from: `whatsapp:${process.env.WHATSAPP_FROM}`,
        to: `whatsapp:${toE164}`,
        body,
        mediaUrl: Array.isArray(mediaUrl) ? mediaUrl : [mediaUrl]
    });
}

const { db, initDatabase } = require('./src/db');
const { ensureRole } = require('./src/middleware/roles');

const app = express();

// View engine and static
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Body parsing
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(methodOverride('_method'));

// Sessions & flash
app.use(session({
	secret: 'super-secret-session',
	resave: false,
	saveUninitialized: false
}));
app.use(flash());

// Passport setup
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy({ usernameField: 'username' }, (username, password, done) => {
	try {
		const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
		if (!user) return done(null, false, { message: 'Invalid credentials' });
		if (!bcrypt.compareSync(password, user.password_hash)) return done(null, false, { message: 'Invalid credentials' });
		return done(null, { id: user.id, username: user.username, role: user.role });
	} catch (e) {
		return done(e);
	}
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
	try {
		const user = db.prepare('SELECT id, username, role FROM users WHERE id = ?').get(id);
		done(null, user);
	} catch (e) {
		done(e);
	}
});

// Expose user & flash to all views
app.use((req, res, next) => {
	res.locals.currentUser = req.user;
	res.locals.success = req.flash('success');
	res.locals.error = req.flash('error');
	next();
});

// Multer for uploads
const storage = multer.diskStorage({
	destination: (req, file, cb) => {
		const dir = path.join(__dirname, 'uploads');
		if (!fs.existsSync(dir)) fs.mkdirSync(dir);
		cb(null, dir);
	},
	filename: (req, file, cb) => {
		const ext = path.extname(file.originalname);
		const base = file.fieldname === 'shopLogo' ? 'logo' : (file.fieldname === 'qrImage' ? 'qr' : (file.fieldname === 'heroImage' ? 'hero' : 'file'));
		cb(null, `${base}${ext}`);
	}
});
const upload = multer({ storage });

function ensureAuthenticated(req, res, next) {
	if (req.isAuthenticated()) return next();
	res.redirect('/login');
}

// Routes
app.get('/', (req, res) => {
    if (req.isAuthenticated && req.isAuthenticated()) {
        const stats = db.prepare('SELECT COUNT(*) as count FROM bills').get();
        const todayTotal = db.prepare("SELECT IFNULL(SUM(total_amount),0) as total FROM bills WHERE DATE(created_at)=DATE('now','localtime')").get();
        const monthTotal = db.prepare("SELECT IFNULL(SUM(total_amount),0) as total FROM bills WHERE strftime('%Y-%m', created_at)=strftime('%Y-%m','now','localtime')").get();
        const pendingBills = []; // placeholder if you later track payment status
        const recentBills = db.prepare('SELECT id, customer_name, total_amount as total, created_at FROM bills ORDER BY created_at DESC LIMIT 8').all();
        const pendingTotal = { total: 0 };
        return res.render('dashboard', { stats, todayTotal, monthTotal, pendingBills, recentBills, pendingTotal, title: 'Dashboard' });
    }
    const settings = db.prepare('SELECT * FROM settings LIMIT 1').get();
    return res.render('home', { settings, title: 'Home' });
});

app.get('/login', (req, res) => {
	if (req.user) return res.redirect('/');
	res.render('login');
});
app.post('/login', passport.authenticate('local', {
	successRedirect: '/',
	failureRedirect: '/login',
	failureFlash: true
}));
app.post('/logout', (req, res, next) => {
	req.logout(err => {
		if (err) return next(err);
		res.redirect('/login');
	});
});

// Products
app.get('/products', ensureAuthenticated, (req, res) => {
	const q = (req.query.q || '').trim();
	const rows = q
		? db.prepare('SELECT * FROM products WHERE name LIKE ? OR sku LIKE ? ORDER BY name ASC').all(`%${q}%`, `%${q}%`)
		: db.prepare('SELECT * FROM products ORDER BY name ASC').all();
	res.render('products', { products: rows, q });
});
app.get('/products/new', ensureAuthenticated, ensureRole(['admin', 'staff']), (req, res) => {
	res.render('product_form', { product: null });
});
app.post('/products', ensureAuthenticated, ensureRole(['admin', 'staff']), (req, res) => {
	const { name, sku, price } = req.body;
	db.prepare('INSERT INTO products (name, sku, price) VALUES (?,?,?)').run(name, sku, Number(price));
	req.flash('success', 'Product created');
	res.redirect('/products');
});
app.get('/products/:id/edit', ensureAuthenticated, ensureRole(['admin', 'staff']), (req, res) => {
	const product = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
	if (!product) return res.redirect('/products');
	res.render('product_form', { product });
});
app.post('/products/:id', ensureAuthenticated, ensureRole(['admin', 'staff']), (req, res) => {
	const { name, sku, price } = req.body;
	db.prepare('UPDATE products SET name=?, sku=?, price=? WHERE id=?').run(name, sku, Number(price), req.params.id);
	req.flash('success', 'Product updated');
	res.redirect('/products');
});
app.post('/products/:id/delete', ensureAuthenticated, ensureRole(['admin']), (req, res) => {
	db.prepare('DELETE FROM products WHERE id = ?').run(req.params.id);
	req.flash('success', 'Product deleted');
	res.redirect('/products');
});

// Bulk upload - products
app.get('/products/bulk', ensureAuthenticated, ensureRole(['admin','staff']), (req, res) => {
	res.render('products_bulk');
});
app.post('/products/bulk', ensureAuthenticated, ensureRole(['admin','staff']), upload.single('excelFile'), (req, res) => {
	if (!XLSX) { req.flash('error', 'Excel parser not available'); return res.redirect('/products/bulk'); }
	if (!req.file) { req.flash('error', 'Please upload an Excel file'); return res.redirect('/products/bulk'); }
	try {
		const buf = req.file.buffer || fs.readFileSync(req.file.path);
		const wb = XLSX.read(buf, { type: 'buffer' });
		const ws = wb.Sheets[wb.SheetNames[0]];
		const rows = XLSX.utils.sheet_to_json(ws, { defval: '' });
		let inserted = 0, updated = 0;
		const upsert = db.prepare('INSERT INTO products (name, sku, price) VALUES (?,?,?) ON CONFLICT(sku) DO UPDATE SET name=excluded.name, price=excluded.price');
		const upsertNoSku = db.prepare('INSERT INTO products (name, price) VALUES (?, ?)');
		const updateNoSku = db.prepare('UPDATE products SET price=? WHERE name=?');
		db.transaction(() => {
			rows.forEach(r => {
				const name = String(r.name || r.Name || r.NAME || '').trim();
				const sku = String(r.sku || r.SKU || r.Sku || '').trim();
				const price = Number(r.price || r.Price || r.PRICE || 0);
				if (!name) return;
				if (sku) {
					try { upsert.run(name, sku, price); inserted++; } catch (e) { updated++; }
				} else {
					const exists = db.prepare('SELECT id FROM products WHERE name=?').get(name);
					if (exists) { updateNoSku.run(price, name); updated++; } else { upsertNoSku.run(name, price); inserted++; }
				}
			});
		})();
		req.flash('success', `Uploaded: ${inserted} added, ${updated} updated`);
		return res.redirect('/products');
	} catch (e) {
		req.flash('error', 'Failed to process the Excel file');
		return res.redirect('/products/bulk');
	}
});

// Downloadable template
app.get('/products/bulk/template', ensureAuthenticated, ensureRole(['admin','staff']), (req, res) => {
    if (!XLSX) { return res.status(503).send('Excel generator not available'); }
    const data = [
        { name: 'Turmeric Powder 1kg', sku: 'HALDI-1KG', price: 240 },
        { name: 'Cumin Seeds 500g', sku: 'CUMIN-500', price: 180 }
    ];
    const ws = XLSX.utils.json_to_sheet(data, { header: ['name','sku','price'] });
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Products');
    const out = XLSX.write(wb, { bookType: 'xlsx', type: 'buffer' });
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', 'attachment; filename="products_template.xlsx"');
    res.send(out);
});

// Billing
app.get('/billing', ensureAuthenticated, ensureRole(['admin', 'staff', 'cashier']), (req, res) => {
	const q = (req.query.q || '').trim();
	const products = q
		? db.prepare('SELECT * FROM products WHERE name LIKE ? OR sku LIKE ? ORDER BY name ASC').all(`%${q}%`, `%${q}%`)
		: db.prepare('SELECT * FROM products ORDER BY name ASC').all();
	const settings = db.prepare('SELECT * FROM settings LIMIT 1').get();
	res.render('billing', { products, settings });
});
app.post('/billing', ensureAuthenticated, ensureRole(['admin', 'staff', 'cashier']), async (req, res) => {
	const { customerName, customerAddress, customerContact, itemsJson } = req.body;
	const items = JSON.parse(itemsJson || '[]');
	let total = 0;
	items.forEach(i => total += Number(i.price) * Number(i.qty));
    const result = db.prepare('INSERT INTO bills (customer_name, customer_address, customer_contact, items_json, total_amount, created_by) VALUES (?,?,?,?,?,?)')
        .run(customerName, customerAddress, customerContact, JSON.stringify(items), total, req.user.username);
    const billId = result.lastInsertRowid;
    try {
        const pdfUrlBase = process.env.PUBLIC_BASE_URL || `http://localhost:${process.env.PORT || 3000}`;
        const settings = db.prepare('SELECT * FROM settings LIMIT 1').get() || {};
        const raw = String(customerContact || '').replace(/[^\d]/g, '');
        const e164 = raw ? (raw.startsWith('91') ? `+${raw}` : `+91${raw}`) : null;

        let sent = false;
        // 1) Try PDF if pdfkit is available
        if (PDFDocument) {
            const pdfPath = path.join(__dirname, 'uploads', `bill-${billId}.pdf`);
            const pdfUrl = `${pdfUrlBase}/uploads/bill-${billId}.pdf`;
            const doc = new PDFDocument({ size: 'A4', margin: 36 });
            const stream = fs.createWriteStream(pdfPath);
            doc.pipe(stream);
            doc.fontSize(18).text(settings.shop_name || 'JJ Traders and Spices', { align: 'left' });
            doc.moveDown(0.2);
            doc.fontSize(10).fillColor('#555').text(`Bill #${billId}`);
            doc.text(`Date: ${(new Date()).toLocaleString()}`);
            doc.moveDown();
            doc.fillColor('#000').fontSize(12).text(`Customer: ${customerName || '-'}`);
            doc.text(`Contact: ${customerContact || '-'}`);
            doc.text(`Address: ${customerAddress || '-'}`);
            doc.moveDown();
            doc.fontSize(12).text('Item', 36, doc.y, { continued: true });
            doc.text('Price', 250, undefined, { continued: true });
            doc.text('Qty', 340, undefined, { continued: true });
            doc.text('Total', 420);
            doc.moveTo(36, doc.y + 2).lineTo(559, doc.y + 2).strokeColor('#eee').stroke();
            items.forEach(it => {
                const lineTotal = Number(it.price) * Number(it.qty);
                doc.moveDown(0.4);
                doc.fillColor('#000').text(String(it.name || ''), 36, doc.y, { continued: true });
                doc.text(Number(it.price).toFixed(2), 250, undefined, { continued: true });
                doc.text(String(it.qty), 340, undefined, { continued: true });
                doc.text(lineTotal.toFixed(2), 420);
            });
            doc.moveDown();
            doc.fontSize(14).text(`Grand Total: ₹ ${total.toFixed(2)}`, { align: 'right' });
            doc.end();
            await new Promise(resolve => stream.on('finish', resolve));
            if (twilioClient && process.env.WHATSAPP_FROM && e164) {
                try { await sendWhatsappMedia(e164, `Your bill #${billId} from JJ Traders and Spices`, pdfUrl); sent = true; } catch (e) {}
            }
        }
        // 2) If not sent, try PNG via puppeteer
        if (!sent && puppeteer && e164) {
            const pngPath = path.join(__dirname, 'uploads', `bill-${billId}.png`);
            await renderBillPng(app, { id: billId, customer_name: customerName, customer_contact: customerContact, customer_address: customerAddress, total_amount: total, created_at: (new Date()).toISOString() }, items, settings, pngPath);
            const pngUrl = `${pdfUrlBase}/uploads/bill-${billId}.png`;
            try { await sendWhatsappMedia(e164, `Your bill #${billId} from JJ Traders and Spices`, pngUrl); sent = true; } catch (e) {}
        }
    } catch (e) {}
    res.redirect(`/bills/${billId}`);
});
app.get('/bills/:id', ensureAuthenticated, (req, res) => {
	const bill = db.prepare('SELECT * FROM bills WHERE id = ?').get(req.params.id);
	if (!bill) return res.redirect('/billing');
	const items = JSON.parse(bill.items_json || '[]');
	const settings = db.prepare('SELECT * FROM settings LIMIT 1').get();
    const whatsappEnabled = !!(twilioClient && process.env.WHATSAPP_FROM);
    res.render('bill_view', { bill, items, settings, whatsappEnabled });
});

// WhatsApp share (link generation)
app.get('/bills/:id/whatsapp', ensureAuthenticated, (req, res) => {
	const bill = db.prepare('SELECT * FROM bills WHERE id = ?').get(req.params.id);
	if (!bill) return res.redirect('/billing');
	const items = JSON.parse(bill.items_json || '[]');
	let msg = `Bill #${bill.id}%0A`;
	items.forEach(i => {
		msg += `${encodeURIComponent(i.name)} x ${i.qty} = ${i.price * i.qty}%0A`;
	});
	msg += `Total: ${bill.total_amount}`;
	const phone = (bill.customer_contact || '').replace(/[^\d]/g, '');
	const url = `https://wa.me/${phone}?text=${msg}`;
	res.redirect(url);
});

// PDF download route
app.get('/bills/:id/pdf', ensureAuthenticated, (req, res) => {
    if (!PDFDocument) { return res.status(503).send('PDF generation not available'); }
    const bill = db.prepare('SELECT * FROM bills WHERE id = ?').get(req.params.id);
    if (!bill) return res.redirect('/billing');
    const items = JSON.parse(bill.items_json || '[]');
    const settings = db.prepare('SELECT * FROM settings LIMIT 1').get() || {};
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `inline; filename=bill-${bill.id}.pdf`);
    const doc = new PDFDocument({ size: 'A4', margin: 36 });
    doc.pipe(res);
    doc.fontSize(18).text(settings.shop_name || 'JJ Traders and Spices', { align: 'left' });
    doc.moveDown(0.2);
    doc.fontSize(10).fillColor('#555').text(`Bill #${bill.id}`);
    doc.text(`Date: ${bill.created_at}`);
    doc.moveDown();
    doc.fillColor('#000').fontSize(12).text(`Customer: ${bill.customer_name || '-'}`);
    doc.text(`Contact: ${bill.customer_contact || '-'}`);
    doc.text(`Address: ${bill.customer_address || '-'}`);
    doc.moveDown();
    doc.fontSize(12).text('Item', 36, doc.y, { continued: true });
    doc.text('Price', 250, undefined, { continued: true });
    doc.text('Qty', 340, undefined, { continued: true });
    doc.text('Total', 420);
    doc.moveTo(36, doc.y + 2).lineTo(559, doc.y + 2).strokeColor('#eee').stroke();
    items.forEach(it => {
        const lineTotal = Number(it.price) * Number(it.qty);
        doc.moveDown(0.4);
        doc.fillColor('#000').text(String(it.name || ''), 36, doc.y, { continued: true });
        doc.text(Number(it.price).toFixed(2), 250, undefined, { continued: true });
        doc.text(String(it.qty), 340, undefined, { continued: true });
        doc.text(lineTotal.toFixed(2), 420);
    });
    doc.moveDown();
    doc.fontSize(14).text(`Grand Total: ₹ ${Number(bill.total_amount).toFixed(2)}`, { align: 'right' });
    doc.end();
});

// History & reports
app.get('/history', ensureAuthenticated, (req, res) => {
	const bills = db.prepare('SELECT * FROM bills ORDER BY created_at DESC LIMIT 200').all();
	res.render('history', { bills });
});
app.get('/reports', ensureAuthenticated, ensureRole(['admin', 'staff']), (req, res) => {
    const group = (req.query.group || 'day'); // 'day' | 'month' | 'date'
    const start = (req.query.start || '').trim();
    const end = (req.query.end || '').trim();
    let rows = [];
    if (group === 'month') {
        if (start && end) {
            rows = db.prepare("SELECT strftime('%Y-%m', created_at) as period, SUM(total_amount) as total, COUNT(*) as num FROM bills WHERE DATE(created_at) BETWEEN DATE(?) AND DATE(?) GROUP BY strftime('%Y-%m', created_at) ORDER BY period DESC").all(start, end);
        } else {
            rows = db.prepare("SELECT strftime('%Y-%m', created_at) as period, SUM(total_amount) as total, COUNT(*) as num FROM bills GROUP BY strftime('%Y-%m', created_at) ORDER BY period DESC LIMIT 12").all();
        }
    } else if (group === 'date') {
        // list bills for a specific date or range
        if (start && end) {
            rows = db.prepare("SELECT id, customer_name, total_amount as total, DATE(created_at) as day FROM bills WHERE DATE(created_at) BETWEEN DATE(?) AND DATE(?) ORDER BY created_at DESC").all(start, end);
        } else {
            rows = db.prepare("SELECT id, customer_name, total_amount as total, DATE(created_at) as day FROM bills WHERE DATE(created_at)=DATE('now','localtime') ORDER BY created_at DESC").all();
        }
    } else {
        if (start && end) {
            rows = db.prepare("SELECT DATE(created_at) as period, SUM(total_amount) as total, COUNT(*) as num FROM bills WHERE DATE(created_at) BETWEEN DATE(?) AND DATE(?) GROUP BY DATE(created_at) ORDER BY period DESC").all(start, end);
        } else {
            rows = db.prepare("SELECT DATE(created_at) as period, SUM(total_amount) as total, COUNT(*) as num FROM bills GROUP BY DATE(created_at) ORDER BY period DESC LIMIT 30").all();
        }
    }
    const summary = db.prepare('SELECT COUNT(*) as count, SUM(total_amount) as revenue FROM bills').get();
    res.render('reports', { rows, summary, group, start, end });
});

// Admin settings: shop profile and images
app.get('/admin/settings', ensureAuthenticated, ensureRole(['admin']), (req, res) => {
	const settings = db.prepare('SELECT * FROM settings LIMIT 1').get();
	res.render('settings', { settings });
});
app.post('/admin/settings', ensureAuthenticated, ensureRole(['admin']), upload.fields([{ name: 'shopLogo' }, { name: 'qrImage' }, { name: 'heroImage' }]), (req, res) => {

	const { shopName, shopContact } = req.body;
	const logoPath = req.files && req.files.shopLogo ? `/uploads/${req.files.shopLogo[0].filename}` : undefined;
	const qrPath = req.files && req.files.qrImage ? `/uploads/${req.files.qrImage[0].filename}` : undefined;
	const heroPath = req.files && req.files.heroImage ? `/uploads/${req.files.heroImage[0].filename}` : undefined;
	const current = db.prepare('SELECT * FROM settings LIMIT 1').get();
	const newLogo = logoPath || (current && current.logo_url) || null;
	const newQr = qrPath || (current && current.qr_url) || null;
	const newHero = heroPath || (current && current.hero_url) || null;
	if (current) {
		db.prepare('UPDATE settings SET shop_name=?, shop_contact=?, logo_url=?, qr_url=?, hero_url=? WHERE id=?')
			.run(shopName, shopContact, newLogo, newQr, newHero, current.id);
	} else {
		db.prepare('INSERT INTO settings (shop_name, shop_contact, logo_url, qr_url, hero_url) VALUES (?,?,?,?,?)')
			.run(shopName, shopContact, newLogo, newQr, newHero);
	}
	req.flash('success', 'Settings updated');
	res.redirect('/admin/settings');
});

// Admin: user management
app.get('/admin/users', ensureAuthenticated, ensureRole(['admin']), (req, res) => {
	const users = db.prepare('SELECT id, username, role FROM users ORDER BY username ASC').all();
	res.render('users', { users });
});
app.get('/admin/users/new', ensureAuthenticated, ensureRole(['admin']), (req, res) => {
	res.render('user_form', { user: null });
});
app.post('/admin/users', ensureAuthenticated, ensureRole(['admin']), (req, res) => {
	const { username, password, role } = req.body;
	if (!['admin','staff','cashier'].includes(role)) { req.flash('error','Invalid role'); return res.redirect('/admin/users/new'); }
	try {
		const hash = bcrypt.hashSync(password, 10);
		db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?,?,?)').run(username, hash, role);
		req.flash('success','User created');
	} catch (e) {
		req.flash('error','Unable to create user (maybe username exists)');
	}
	res.redirect('/admin/users');
});
app.get('/admin/users/:id/edit', ensureAuthenticated, ensureRole(['admin']), (req, res) => {
	const user = db.prepare('SELECT id, username, role FROM users WHERE id = ?').get(req.params.id);
	if (!user) return res.redirect('/admin/users');
	res.render('user_form', { user });
});
app.post('/admin/users/:id', ensureAuthenticated, ensureRole(['admin']), (req, res) => {
	const { username, role, password } = req.body;
	if (!['admin','staff','cashier'].includes(role)) { req.flash('error','Invalid role'); return res.redirect(`/admin/users/${req.params.id}/edit`); }
	try {
		if (password && password.trim().length > 0) {
			const hash = bcrypt.hashSync(password, 10);
			db.prepare('UPDATE users SET username=?, role=?, password_hash=? WHERE id=?').run(username, role, hash, req.params.id);
		} else {
			db.prepare('UPDATE users SET username=?, role=? WHERE id=?').run(username, role, req.params.id);
		}
		req.flash('success','User updated');
	} catch (e) {
		req.flash('error','Unable to update user');
	}
	res.redirect('/admin/users');
});
app.post('/admin/users/:id/delete', ensureAuthenticated, ensureRole(['admin']), (req, res) => {
	const id = Number(req.params.id);
	if (req.user && req.user.id === id) { req.flash('error','You cannot delete your own account'); return res.redirect('/admin/users'); }
	db.prepare('DELETE FROM users WHERE id = ?').run(id);
	req.flash('success','User deleted');
	res.redirect('/admin/users');
});

// Bootstrap DB and server
initDatabase();

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
	console.log(`Server running on http://localhost:${PORT}`);
});


// Error handler (friendly message instead of 500 crash page)
app.use((err, req, res, next) => {
    console.error('Internal error:', err);
    res.status(500).send('Something went wrong. Please try again.');
});

