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
		const base = file.fieldname === 'shopLogo' ? 'logo' : (file.fieldname === 'qrImage' ? 'qr' : 'file');
		cb(null, `${base}${ext}`);
	}
});
const upload = multer({ storage });

function ensureAuthenticated(req, res, next) {
	if (req.isAuthenticated()) return next();
	res.redirect('/login');
}

// Routes
app.get('/', ensureAuthenticated, (req, res) => {
	const stats = db.prepare('SELECT COUNT(*) as count FROM bills').get();
	const todayTotal = db.prepare("SELECT IFNULL(SUM(total_amount),0) as total FROM bills WHERE DATE(created_at)=DATE('now','localtime')").get();
	res.render('dashboard', { stats, todayTotal });
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

// Billing
app.get('/billing', ensureAuthenticated, ensureRole(['admin', 'staff', 'cashier']), (req, res) => {
	const q = (req.query.q || '').trim();
	const products = q
		? db.prepare('SELECT * FROM products WHERE name LIKE ? OR sku LIKE ? ORDER BY name ASC').all(`%${q}%`, `%${q}%`)
		: db.prepare('SELECT * FROM products ORDER BY name ASC').all();
	const settings = db.prepare('SELECT * FROM settings LIMIT 1').get();
	res.render('billing', { products, settings });
});
app.post('/billing', ensureAuthenticated, ensureRole(['admin', 'staff', 'cashier']), (req, res) => {
	const { customerName, customerAddress, customerContact, itemsJson } = req.body;
	const items = JSON.parse(itemsJson || '[]');
	let total = 0;
	items.forEach(i => total += Number(i.price) * Number(i.qty));
	const result = db.prepare('INSERT INTO bills (customer_name, customer_address, customer_contact, items_json, total_amount, created_by) VALUES (?,?,?,?,?,?)')
		.run(customerName, customerAddress, customerContact, JSON.stringify(items), total, req.user.username);
	res.redirect(`/bills/${result.lastInsertRowid}`);
});
app.get('/bills/:id', ensureAuthenticated, (req, res) => {
	const bill = db.prepare('SELECT * FROM bills WHERE id = ?').get(req.params.id);
	if (!bill) return res.redirect('/billing');
	const items = JSON.parse(bill.items_json || '[]');
	const settings = db.prepare('SELECT * FROM settings LIMIT 1').get();
	res.render('bill_view', { bill, items, settings });
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

// History & reports
app.get('/history', ensureAuthenticated, (req, res) => {
	const bills = db.prepare('SELECT * FROM bills ORDER BY created_at DESC LIMIT 200').all();
	res.render('history', { bills });
});
app.get('/reports', ensureAuthenticated, ensureRole(['admin', 'staff']), (req, res) => {
	const daily = db.prepare("SELECT DATE(created_at) as day, SUM(total_amount) as total, COUNT(*) as num FROM bills GROUP BY DATE(created_at) ORDER BY day DESC LIMIT 30").all();
	const summary = db.prepare('SELECT COUNT(*) as count, SUM(total_amount) as revenue FROM bills').get();
	res.render('reports', { daily, summary });
});

// Admin settings: shop profile and images
app.get('/admin/settings', ensureAuthenticated, ensureRole(['admin']), (req, res) => {
	const settings = db.prepare('SELECT * FROM settings LIMIT 1').get();
	res.render('settings', { settings });
});
app.post('/admin/settings', ensureAuthenticated, ensureRole(['admin']), upload.fields([{ name: 'shopLogo' }, { name: 'qrImage' }]), (req, res) => {
	const { shopName, shopContact } = req.body;
	const logoPath = req.files && req.files.shopLogo ? `/uploads/${req.files.shopLogo[0].filename}` : undefined;
	const qrPath = req.files && req.files.qrImage ? `/uploads/${req.files.qrImage[0].filename}` : undefined;
	const current = db.prepare('SELECT * FROM settings LIMIT 1').get();
	const newLogo = logoPath || (current && current.logo_url) || null;
	const newQr = qrPath || (current && current.qr_url) || null;
	if (current) {
		db.prepare('UPDATE settings SET shop_name=?, shop_contact=?, logo_url=?, qr_url=? WHERE id=?')
			.run(shopName, shopContact, newLogo, newQr, current.id);
	} else {
		db.prepare('INSERT INTO settings (shop_name, shop_contact, logo_url, qr_url) VALUES (?,?,?,?)')
			.run(shopName, shopContact, newLogo, newQr);
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


