const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');

const dbPath = path.join(__dirname, '..', 'data.sqlite');
const db = new Database(dbPath);

function initDatabase() {
	db.prepare(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL CHECK(role IN ('admin','staff','cashier'))
	)`).run();

	db.prepare(`CREATE TABLE IF NOT EXISTS products (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		sku TEXT UNIQUE,
		price REAL NOT NULL DEFAULT 0
	)`).run();

	db.prepare(`CREATE TABLE IF NOT EXISTS bills (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		customer_name TEXT,
		customer_address TEXT,
		customer_contact TEXT,
		items_json TEXT NOT NULL,
		total_amount REAL NOT NULL,
		created_by TEXT,
		created_at DATETIME DEFAULT (datetime('now','localtime'))
	)`).run();

	db.prepare(`CREATE TABLE IF NOT EXISTS settings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		shop_name TEXT,
		shop_contact TEXT,
		logo_url TEXT,
		qr_url TEXT
	)`).run();

	// Seed admin if none
	const count = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
	if (count === 0) {
		const hash = bcrypt.hashSync('admin123', 10);
		db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?,?,?)')
			.run('admin', hash, 'admin');
	}

	// Seed settings if empty
	const settings = db.prepare('SELECT COUNT(*) as c FROM settings').get().c;
	if (settings === 0) {
		db.prepare('INSERT INTO settings (shop_name, shop_contact, logo_url, qr_url) VALUES (?,?,?,?)')
			.run('My Shop', '+91 90000 00000', null, null);
	}
}

module.exports = { db, initDatabase };


