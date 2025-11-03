# Billing Website (Admin/Staff/Cashier)

Mobile-friendly billing system with multi-role login, product CRUD, billing, WhatsApp share, admin settings for logo/QR, history, and reports.

## Features
- Admin, Staff, Cashier roles (local auth)
- Product CRUD with search and price updates
- Billing: select items, customer details, generate bill
- Share bill through WhatsApp (opens `wa.me` with pre-filled message)
- Admin settings: shop name/contact, upload logo and QR image
- Billing history and daily reports
- Responsive, mobile-first UI

## Tech
- Node.js, Express, EJS
- SQLite (better-sqlite3)
- Passport Local, Multer

## Setup
```bash
npm install
npm run dev
# open http://localhost:3000
```

Default admin: `admin` / `admin123`

## File Uploads
- Uploaded files saved in `uploads/`
- Admin can update logo and QR from Admin → Settings

## Notes
- To add staff/cashier users, insert into `users` table with roles `staff` or `cashier`.


