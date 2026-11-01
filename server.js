require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const db = new Database("data.sqlite");
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT);
CREATE TABLE IF NOT EXISTS menu (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, category TEXT NOT NULL, description TEXT DEFAULT '', price INTEGER NOT NULL, image TEXT DEFAULT '', available INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS rooms (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT DEFAULT '', price INTEGER NOT NULL, image TEXT DEFAULT '', capacity INTEGER DEFAULT 2, available INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY AUTOINCREMENT, customer TEXT, phone TEXT, address TEXT, items TEXT, total INTEGER, status TEXT DEFAULT 'Received', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS bookings (id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT, customer TEXT, phone TEXT, date TEXT, time TEXT, guests INTEGER, room TEXT, notes TEXT, status TEXT DEFAULT 'Pending', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
`);
const adminUser = process.env.ADMIN_USERNAME || "owner";
const adminPass = process.env.ADMIN_PASSWORD;
if (adminPass) {
  const exists = db.prepare("SELECT id FROM admins WHERE username=?").get(adminUser);
  if (!exists) db.prepare("INSERT INTO admins(username,password_hash) VALUES(?,?)").run(adminUser, bcrypt.hashSync(adminPass, 12));
}
const seedMenu = [
 ["Chicken Karahi","Traditional", "Classic Pakistani chicken karahi, served fresh",1850,"https://images.unsplash.com/photo-1603894584373-5ac82b2ae398?w=900"],
 ["Chicken Biryani","Traditional", "Aromatic basmati rice with traditional spices",450,"https://images.unsplash.com/photo-1563379091339-03246963d96c?w=900"],
 ["Beef Karahi","Traditional", "Rich, slow-cooked beef karahi",2200,"https://images.unsplash.com/photo-1545247181-516773cae754?w=900"],
 ["Mutton Qorma","Traditional", "Traditional qorma with fragrant spices",2400,"https://images.unsplash.com/photo-1565557623262-b51c2513a641?w=900"],
 ["BBQ Platter","BBQ", "A selection of freshly grilled favourites",1850,"https://images.unsplash.com/photo-1529193591184-b1d58069ecdd?w=900"],
 ["Chicken Burger","Fast Food", "Crispy chicken, fresh lettuce and house sauce",550,"https://images.unsplash.com/photo-1568901346375-23c9450c58cd?w=900"],
 ["Fresh Lime","Drinks", "Refreshing fresh lime drink",180,"https://images.unsplash.com/photo-1513558161293-caus6f4f9a0e?w=900"]
];
if (!db.prepare("SELECT id FROM menu LIMIT 1").get()) {
 const ins=db.prepare("INSERT INTO menu(name,category,description,price,image) VALUES(?,?,?,?,?)");
 seedMenu.forEach(x=>ins.run(...x));
}
const seedRooms = [
 ["Deluxe Room","Comfortable stay with modern essentials and a relaxing atmosphere",6500,"https://images.unsplash.com/photo-1611892440504-42a792e24d32?w=1200",2],
 ["Executive Room","An elevated room experience for business and leisure guests",8500,"https://images.unsplash.com/photo-1616486338812-3dadae4b4ace?w=1200",2],
 ["Family Suite","Spacious accommodation for families and group stays",12000,"https://images.unsplash.com/photo-1618221195710-dd6b41faaea6?w=1200",4]
];
if (!db.prepare("SELECT id FROM rooms LIMIT 1").get()) {
 const ins=db.prepare("INSERT INTO rooms(name,description,price,image,capacity) VALUES(?,?,?,?,?)");
 seedRooms.forEach(x=>ins.run(...x));
}
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({limit:"1mb"}));
app.use(express.urlencoded({extended:true}));
app.use(session({
 secret: process.env.SESSION_SECRET || "development-only-change-me",
 resave:false, saveUninitialized:false,
 store:new SQLiteStore({db:"sessions.sqlite"}),
 cookie:{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:8*60*60*1000}
}));
app.use("/api/admin/login", rateLimit({windowMs:15*60*1000, max:8}));
const adminOnly=(req,res,next)=>req.session.admin ? next() : res.status(401).json({error:"Please sign in as admin."});

app.get("/api/menu",(req,res)=>res.json(db.prepare("SELECT * FROM menu WHERE available=1 ORDER BY category,name").all()));
app.get("/api/rooms",(req,res)=>res.json(db.prepare("SELECT * FROM rooms WHERE available=1 ORDER BY price").all()));
app.post("/api/orders",(req,res)=>{
 const {customer,phone,address,items,total}=req.body||{};
 if(!customer||!phone||!address||!Array.isArray(items)||!items.length||!Number.isFinite(Number(total))) return res.status(400).json({error:"Please complete all order details."});
 const info=db.prepare("INSERT INTO orders(customer,phone,address,items,total) VALUES(?,?,?,?,?)").run(String(customer).slice(0,100),String(phone).slice(0,30),String(address).slice(0,500),JSON.stringify(items),Math.max(0,Math.round(total)));
 res.status(201).json({id:info.lastInsertRowid,status:"Received"});
});
app.post("/api/bookings",(req,res)=>{
 const {type,customer,phone,date,time,guests,room,notes}=req.body||{};
 if(!["room","table"].includes(type)||!customer||!phone||!date||!guests) return res.status(400).json({error:"Please complete the required booking details."});
 const info=db.prepare("INSERT INTO bookings(type,customer,phone,date,time,guests,room,notes) VALUES(?,?,?,?,?,?,?,?)").run(type,String(customer).slice(0,100),String(phone).slice(0,30),String(date).slice(0,20),String(time||"").slice(0,20),Math.max(1,Math.min(30,Number(guests)||1)),String(room||"").slice(0,100),String(notes||"").slice(0,500));
 res.status(201).json({id:info.lastInsertRowid,status:"Pending"});
});
app.post("/api/admin/login", (req,res)=>{
 const {username,password}=req.body||{};
 const row=db.prepare("SELECT * FROM admins WHERE username=?").get(String(username||""));
 if(!row||!bcrypt.compareSync(String(password||""),row.password_hash)) return res.status(401).json({error:"Incorrect username or password."});
 req.session.regenerate(err=>{if(err)return res.status(500).json({error:"Could not start session."});req.session.admin={id:row.id,username:row.username};res.json({username:row.username});});
});
app.post("/api/admin/logout",adminOnly,(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/admin/me",(req,res)=>res.json({authenticated:!!req.session.admin,username:req.session.admin?.username||null}));
app.get("/api/admin/orders",adminOnly,(req,res)=>res.json(db.prepare("SELECT * FROM orders ORDER BY id DESC LIMIT 300").all()));
app.get("/api/admin/bookings",adminOnly,(req,res)=>res.json(db.prepare("SELECT * FROM bookings ORDER BY id DESC LIMIT 300").all()));
app.patch("/api/admin/orders/:id",adminOnly,(req,res)=>{
 const allowed=["Received","Preparing","Out for delivery","Completed","Cancelled"];
 if(!allowed.includes(req.body.status))return res.status(400).json({error:"Invalid status"});
 db.prepare("UPDATE orders SET status=? WHERE id=?").run(req.body.status,req.params.id);res.json({ok:true});
});
app.patch("/api/admin/bookings/:id",adminOnly,(req,res)=>{
 const allowed=["Pending","Confirmed","Completed","Cancelled"];
 if(!allowed.includes(req.body.status))return res.status(400).json({error:"Invalid status"});
 db.prepare("UPDATE bookings SET status=? WHERE id=?").run(req.body.status,req.params.id);res.json({ok:true});
});
app.get("/api/admin/menu",adminOnly,(req,res)=>res.json(db.prepare("SELECT * FROM menu ORDER BY id DESC").all()));
app.post("/api/admin/menu",adminOnly,(req,res)=>{
 const {name,category,description,price,image,available}=req.body||{};
 if(!name||!category||!Number.isFinite(Number(price)))return res.status(400).json({error:"Name, category and price are required."});
 const info=db.prepare("INSERT INTO menu(name,category,description,price,image,available) VALUES(?,?,?,?,?,?)").run(String(name).slice(0,100),String(category).slice(0,50),String(description||"").slice(0,500),Math.max(0,Math.round(price)),String(image||"").slice(0,1000),available===false?0:1);
 res.status(201).json({id:info.lastInsertRowid});
});
app.put("/api/admin/menu/:id",adminOnly,(req,res)=>{
 const {name,category,description,price,image,available}=req.body||{};
 if(!name||!category||!Number.isFinite(Number(price)))return res.status(400).json({error:"Name, category and price are required."});
 db.prepare("UPDATE menu SET name=?,category=?,description=?,price=?,image=?,available=? WHERE id=?").run(String(name).slice(0,100),String(category).slice(0,50),String(description||"").slice(0,500),Math.max(0,Math.round(price)),String(image||"").slice(0,1000),available===false?0:1,req.params.id);res.json({ok:true});
});
app.delete("/api/admin/menu/:id",adminOnly,(req,res)=>{db.prepare("DELETE FROM menu WHERE id=?").run(req.params.id);res.json({ok:true});});
app.get("/api/admin/rooms",adminOnly,(req,res)=>res.json(db.prepare("SELECT * FROM rooms ORDER BY id DESC").all()));
app.post("/api/admin/rooms",adminOnly,(req,res)=>{
 const {name,description,price,image,capacity,available}=req.body||{};
 if(!name||!Number.isFinite(Number(price)))return res.status(400).json({error:"Name and price are required."});
 const info=db.prepare("INSERT INTO rooms(name,description,price,image,capacity,available) VALUES(?,?,?,?,?,?)").run(String(name).slice(0,100),String(description||"").slice(0,500),Math.max(0,Math.round(price)),String(image||"").slice(0,1000),Math.max(1,Math.min(20,Number(capacity)||2)),available===false?0:1);res.status(201).json({id:info.lastInsertRowid});
});
app.put("/api/admin/rooms/:id",adminOnly,(req,res)=>{
 const {name,description,price,image,capacity,available}=req.body||{};
 if(!name||!Number.isFinite(Number(price)))return res.status(400).json({error:"Name and price are required."});
 db.prepare("UPDATE rooms SET name=?,description=?,price=?,image=?,capacity=?,available=? WHERE id=?").run(String(name).slice(0,100),String(description||"").slice(0,500),Math.max(0,Math.round(price)),String(image||"").slice(0,1000),Math.max(1,Math.min(20,Number(capacity)||2)),available===false?0:1,req.params.id);res.json({ok:true});
});
app.delete("/api/admin/rooms/:id",adminOnly,(req,res)=>{db.prepare("DELETE FROM rooms WHERE id=?").run(req.params.id);res.json({ok:true});});
app.use(express.static(path.join(__dirname,"public")));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
const port=Number(process.env.PORT)||3000;
app.listen(port,()=>console.log(`BHUTTA HOTEL website running at http://localhost:${port}`));
