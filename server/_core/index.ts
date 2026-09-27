import express from "express";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { registerStorageProxy } from "./storageProxy";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const isBundled = fs.existsSync(path.join(__dirname, "public"));
const ROOT = isBundled ? path.resolve(__dirname, "..") : path.resolve(__dirname, "../..");
const PUBLIC_DIR = isBundled ? path.join(__dirname, "public") : path.join(ROOT, "client", "public");
const DATA_DIR = path.join(ROOT, "data");
const DATA_FILE = path.join(DATA_DIR, "db.json");
const INITIAL_DATA_FILE = path.join(PUBLIC_DIR, "site-data", "db.json");
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");
const ADMIN_USERNAME = String(process.env.ADMIN_USERNAME || "alton").trim();
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || "");

const app = express();
app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true, limit: "5mb" }));
registerStorageProxy(app);

const defaults = {
  admins: [], users: [], categories: [], streams: [], vods: [], series: [], episodes: [],
  subscriptions: [], subscriptionRequests: [],
  plans: [
    { code: "monthly", name: "الباقة الشهرية", durationDays: 30, price: 50, originalPrice: 100, badge: "عرض الشهر" },
    { code: "yearly", name: "الباقة السنوية", durationDays: 365, price: 300, originalPrice: null, badge: "أفضل قيمة" }
  ]
};

type AnyData = Record<string, any>;
let writeQueue: Promise<unknown> = Promise.resolve();

function uid() { return crypto.randomUUID(); }
function now() { return new Date().toISOString(); }
function safeJson(value: unknown) { return JSON.stringify(value, null, 2); }

function normalizeData(input: AnyData | null | undefined): AnyData {
  const data: AnyData = { ...defaults, ...(input || {}) };
  for (const key of Object.keys(defaults)) {
    if (key === "plans") continue;
    if (!Array.isArray(data[key])) data[key] = [];
  }
  if (!Array.isArray(data.plans) || !data.plans.length) data.plans = defaults.plans;
  return data;
}

function loadData(): AnyData {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DATA_FILE)) {
    if (fs.existsSync(INITIAL_DATA_FILE)) fs.copyFileSync(INITIAL_DATA_FILE, DATA_FILE);
    else fs.writeFileSync(DATA_FILE, safeJson(defaults));
  }
  try { return normalizeData(JSON.parse(fs.readFileSync(DATA_FILE, "utf8"))); }
  catch { return normalizeData(defaults); }
}

function saveData(data: AnyData) {
  const payload = safeJson(normalizeData(data));
  writeQueue = writeQueue.then(async () => {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const temp = `${DATA_FILE}.tmp`;
    fs.writeFileSync(temp, payload);
    fs.renameSync(temp, DATA_FILE);
  });
  return writeQueue;
}

function signToken(payload: AnyData) {
  const body = Buffer.from(JSON.stringify({ ...payload, iat: Date.now() })).toString("base64url");
  const sig = crypto.createHmac("sha256", JWT_SECRET).update(body).digest("base64url");
  return `${body}.${sig}`;
}
function verifyToken(token?: string) {
  if (!token) return null;
  const [body, sig] = token.split(".");
  if (!body || !sig) return null;
  const expected = crypto.createHmac("sha256", JWT_SECRET).update(body).digest("base64url");
  if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    const value = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (Date.now() - Number(value.iat || 0) > 12 * 60 * 60 * 1000) return null;
    return value;
  } catch { return null; }
}
function cookies(req: express.Request) {
  return Object.fromEntries(String(req.headers.cookie || "").split(";").filter(Boolean).map(part => {
    const [key, ...rest] = part.trim().split("=");
    return [key, decodeURIComponent(rest.join("=") || "")];
  }));
}
function setCookie(res: express.Response, name: string, value: string, maxAge = 60 * 60 * 12) {
  res.setHeader("Set-Cookie", `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}; Secure`);
}
function clearCookie(res: express.Response, name: string) {
  res.setHeader("Set-Cookie", `${name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Secure`);
}

function hashPassword(password: string) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64);
  return `scrypt$${salt.toString("base64url")}$${hash.toString("base64url")}`;
}
function verifyPassword(password: string, encoded: string) {
  try {
    const [scheme, saltText, hashText] = String(encoded || "").split("$");
    if (scheme !== "scrypt" || !saltText || !hashText) return false;
    const salt = Buffer.from(saltText, "base64url");
    const expected = Buffer.from(hashText, "base64url");
    const actual = crypto.scryptSync(password, salt, expected.length);
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  } catch { return false; }
}
function userActive(user: AnyData | undefined) {
  return !!user?.enabled && (!user.expiresAt || new Date(user.expiresAt).getTime() > Date.now());
}
function publicUser(user: AnyData | undefined) {
  if (!user) return null;
  return { id: user.id, username: user.username, displayName: user.displayName || "", notes: user.notes || "", createdAt: user.createdAt, expiresAt: user.expiresAt || null, maxConnections: user.maxConnections || 1, enabled: !!user.enabled, isTrial: !!user.isTrial };
}
function findUser(data: AnyData, username: string, password: string) {
  const user = data.users.find((candidate: AnyData) => String(candidate.username).toLowerCase() === username.toLowerCase());
  return user && verifyPassword(password, user.passwordHash) ? user : null;
}
function isAdmin(req: express.Request) { return verifyToken(cookies(req).admin_token)?.type === "admin"; }
function currentUser(req: express.Request, data = loadData()) {
  const token = verifyToken(cookies(req).user_token);
  const user = token?.type === "user" ? data.users.find((item: AnyData) => item.id === token.sub) : null;
  return user && userActive(user) ? user : null;
}
function requireAdmin(req: express.Request, res: express.Response, next: express.NextFunction) {
  if (!isAdmin(req)) return res.status(401).json({ error: "يجب تسجيل دخول المشرف أولًا" });
  next();
}
function requireMember(req: express.Request, res: express.Response, next: express.NextFunction) {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "سجّل الدخول بحساب Xtream فعال للمتابعة" });
  (req as any).member = user;
  next();
}
function requireViewer(req: express.Request, res: express.Response, next: express.NextFunction) {
  if (isAdmin(req)) { (req as any).viewerRole = "admin"; return next(); }
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "الدخول للقنوات متاح للمشرف أو الأعضاء المسجلين فقط" });
  (req as any).member = user;
  (req as any).viewerRole = "member";
  next();
}
function planByCode(data: AnyData, code: string) { return data.plans.find((plan: AnyData) => plan.code === code); }
function xtreamResponse(user: AnyData | null, password: string, req: express.Request) {
  const active = userActive(user || undefined);
  return {
    user_info: user ? { username: user.username, password, auth: active ? 1 : 0, status: active ? "Active" : "Disabled", message: active ? "Welcome" : "Account expired or disabled", exp_date: user.expiresAt ? Math.floor(new Date(user.expiresAt).getTime() / 1000) : 0, is_trial: user.isTrial ? "1" : "0", active_cons: "0", max_connections: String(user.maxConnections || 1), created_at: Math.floor(new Date(user.createdAt || now()).getTime() / 1000), allowed_output_formats: ["m3u8", "ts"] } : { auth: 0, status: "Disabled", message: "Invalid credentials" },
    server_info: { url: `${req.protocol}://${req.get("host")}`, port: String(PORT), https_port: String(PORT), server_protocol: req.protocol, timezone: "Africa/Cairo", time_now: now(), timestamp_now: Math.floor(Date.now() / 1000) }
  };
}
function logLogin(type: string, username: string, success: boolean) { console.log(JSON.stringify({ event: "login", type, username, success, at: now() })); }

app.get("/health", (_req, res) => res.json({ ok: true, service: "SHEPO IPTV", auth: "enabled" }));
app.get("/api/storage-status", (_req, res) => res.json({ ok: true, storage: "local-json", message: "البيانات محفوظة في ملف قاعدة بيانات المشروع" }));

app.post("/api/admin/login", (req, res) => {
  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");
  const ok = !!ADMIN_PASSWORD && username === ADMIN_USERNAME && password === ADMIN_PASSWORD;
  logLogin("admin", username, ok);
  if (!ok) return res.status(401).json({ error: "بيانات المشرف غير صحيحة" });
  setCookie(res, "admin_token", signToken({ type: "admin", sub: ADMIN_USERNAME, username: ADMIN_USERNAME }));
  res.json({ ok: true, username: ADMIN_USERNAME });
});
app.post("/api/login", (req, res) => {
  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");
  const ok = !!ADMIN_PASSWORD && username === ADMIN_USERNAME && password === ADMIN_PASSWORD;
  if (!ok) return res.status(401).json({ error: "بيانات المشرف غير صحيحة" });
  setCookie(res, "admin_token", signToken({ type: "admin", sub: ADMIN_USERNAME, username: ADMIN_USERNAME }));
  res.json({ ok: true, username: ADMIN_USERNAME });
});
app.post("/api/admin/logout", (_req, res) => { clearCookie(res, "admin_token"); res.json({ ok: true }); });
app.post("/api/logout", (_req, res) => { clearCookie(res, "admin_token"); res.json({ ok: true }); });
app.get("/api/admin/me", (req, res) => { const token = verifyToken(cookies(req).admin_token); if (token?.type !== "admin") return res.status(401).json({ error: "غير مسجل" }); res.json({ ok: true, username: token.username }); });
app.get("/api/me", (req, res) => { const token = verifyToken(cookies(req).admin_token); if (token?.type !== "admin") return res.status(401).json({ error: "غير مسجل" }); res.json({ ok: true, username: token.username }); });

app.post("/api/public/login", (req, res) => {
  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");
  const data = loadData();
  const user = findUser(data, username, password);
  const ok = !!user && userActive(user);
  logLogin("member", username, ok);
  if (!ok) return res.status(401).json({ error: "بيانات Xtream غير صحيحة أو الحساب منتهي/موقوف" });
  setCookie(res, "user_token", signToken({ type: "user", sub: user.id, username: user.username }));
  res.json({ ok: true, user: publicUser(user) });
});
app.post("/api/public/logout", (_req, res) => { clearCookie(res, "user_token"); res.json({ ok: true }); });
app.get("/api/public/me", (req, res) => { const user = currentUser(req); const admin = isAdmin(req); res.json({ ok: true, guest: !user && !admin, role: admin ? "admin" : user ? "member" : "guest", admin, user: publicUser(user || undefined) }); });
app.post("/api/public/subscriptions", requireMember, async (req, res) => {
  const data = loadData();
  const plan = planByCode(data, String(req.body?.planCode || ""));
  if (!plan) return res.status(400).json({ error: "الباقة غير موجودة" });
  const user = (req as any).member;
  const request = { id: uid(), userId: user.id, planCode: plan.code, planName: plan.name, amount: plan.price, status: "pending", requestedAt: now() };
  data.subscriptionRequests.push(request);
  await saveData(data);
  res.json({ ok: true, request, message: "تم إرسال طلب الاشتراك، وسيتم تفعيله من لوحة المشرف" });
});

app.get("/api/stats", requireAdmin, (_req, res) => { const data = loadData(); res.json({ users: data.users.length, activeUsers: data.users.filter(userActive).length, live: data.streams.length, movies: data.vods.length, series: data.series.length, categories: data.categories.length, pendingSubscriptions: data.subscriptionRequests.filter((item: AnyData) => item.status === "pending").length }); });
app.get("/api/users", requireAdmin, (_req, res) => res.json(loadData().users.map(publicUser)));
app.post("/api/users", requireAdmin, async (req, res) => {
  const cleanName = String(req.body?.username || "").trim();
  const cleanPassword = String(req.body?.password || "");
  if (!/^[A-Za-z0-9_.-]{3,32}$/.test(cleanName)) return res.status(400).json({ error: "اسم المستخدم يجب أن يكون من 3 إلى 32 حرفًا إنجليزيًا أو أرقامًا أو _.-" });
  if (cleanPassword.length < 6) return res.status(400).json({ error: "كلمة المرور يجب أن تكون 6 أحرف على الأقل" });
  const data = loadData();
  if (data.users.some((item: AnyData) => item.username.toLowerCase() === cleanName.toLowerCase())) return res.status(409).json({ error: "اسم المستخدم موجود بالفعل" });
  const user = { id: uid(), username: cleanName, displayName: String(req.body?.displayName || "").trim(), notes: String(req.body?.notes || "").trim(), passwordHash: hashPassword(cleanPassword), createdAt: now(), expiresAt: req.body?.expiresAt || null, maxConnections: Math.max(1, Number(req.body?.maxConnections) || 1), enabled: req.body?.enabled !== false, isTrial: !!req.body?.isTrial };
  data.users.push(user); await saveData(data);
  const origin = `${req.protocol}://${req.get("host")}`;
  res.json({ ok: true, user: publicUser(user), credentials: { username: user.username, password: cleanPassword, serverUrl: origin, playerApiUrl: `${origin}/player_api.php?username=${encodeURIComponent(user.username)}&password=${encodeURIComponent(cleanPassword)}`, m3uUrl: `${origin}/get.php?username=${encodeURIComponent(user.username)}&password=${encodeURIComponent(cleanPassword)}&type=m3u_plus` } });
});
app.patch("/api/users/:id", requireAdmin, async (req, res) => { const data = loadData(); const user = data.users.find((item: AnyData) => item.id === req.params.id); if (!user) return res.status(404).json({ error: "المستخدم غير موجود" }); for (const field of ["displayName", "notes", "expiresAt", "maxConnections", "enabled", "isTrial"]) if (field in req.body) user[field] = field === "maxConnections" ? Math.max(1, Number(req.body[field]) || 1) : req.body[field]; if (req.body?.password) user.passwordHash = hashPassword(String(req.body.password)); await saveData(data); res.json({ ok: true, user: publicUser(user) }); });
app.delete("/api/users/:id", requireAdmin, async (req, res) => { const data = loadData(); data.users = data.users.filter((item: AnyData) => item.id !== req.params.id); data.subscriptionRequests = data.subscriptionRequests.filter((item: AnyData) => item.userId !== req.params.id); await saveData(data); res.json({ ok: true }); });

app.get("/api/subscriptions", requireAdmin, (_req, res) => { const data = loadData(); res.json(data.subscriptionRequests.map((item: AnyData) => ({ ...item, username: data.users.find((user: AnyData) => user.id === item.userId)?.username || "-" }))); });
app.patch("/api/subscriptions/:id", requireAdmin, async (req, res) => { const data = loadData(); const request = data.subscriptionRequests.find((item: AnyData) => item.id === req.params.id); if (!request) return res.status(404).json({ error: "طلب الاشتراك غير موجود" }); const nextStatus = String(req.body?.status || ""); if (!["active", "rejected", "pending"].includes(nextStatus)) return res.status(400).json({ error: "حالة غير صالحة" }); request.status = nextStatus; request.updatedAt = now(); if (nextStatus === "active") { const user = data.users.find((item: AnyData) => item.id === request.userId); const plan = planByCode(data, request.planCode); if (user && plan) { const current = user.expiresAt && new Date(user.expiresAt).getTime() > Date.now() ? new Date(user.expiresAt).getTime() : new Date().getTime(); user.expiresAt = new Date(current + Number(plan.durationDays) * 86400000).toISOString(); user.enabled = true; request.activatedAt = now(); } } await saveData(data); res.json({ ok: true, request }); });

app.get("/api/categories", requireAdmin, (_req, res) => res.json(loadData().categories));
app.post("/api/categories", requireAdmin, async (req, res) => { if (!req.body?.name) return res.status(400).json({ error: "الاسم مطلوب" }); const data = loadData(); const category = { id: uid(), name: String(req.body.name), type: ["live", "vod", "series"].includes(req.body.type) ? req.body.type : "live" }; data.categories.push(category); await saveData(data); res.json(category); });
app.delete("/api/categories/:id", requireAdmin, async (req, res) => { const data = loadData(); data.categories = data.categories.filter((item: AnyData) => item.id !== req.params.id); await saveData(data); res.json({ ok: true }); });
app.get("/api/streams", requireAdmin, (_req, res) => res.json(loadData().streams));
app.post("/api/streams", requireAdmin, async (req, res) => { if (!req.body?.name || !req.body?.url) return res.status(400).json({ error: "اسم القناة والرابط مطلوبان" }); const data = loadData(); const stream = { id: uid(), name: String(req.body.name), url: String(req.body.url), categoryId: String(req.body.categoryId || ""), logo: String(req.body.logo || ""), streamIcon: String(req.body.logo || ""), containerExtension: /\.m3u8/i.test(req.body.url) ? "m3u8" : "ts" }; data.streams.push(stream); await saveData(data); res.json(stream); });
app.delete("/api/streams/:id", requireAdmin, async (req, res) => { const data = loadData(); data.streams = data.streams.filter((item: AnyData) => item.id !== req.params.id); await saveData(data); res.json({ ok: true }); });
app.delete("/api/streams", requireAdmin, async (_req, res) => { const data = loadData(); data.streams = []; data.categories = data.categories.filter((item: AnyData) => item.type !== "live"); await saveData(data); res.json({ ok: true }); });
app.post("/api/replace-with-bundled-catalog", requireAdmin, async (_req, res) => { const original = fs.existsSync(INITIAL_DATA_FILE) ? normalizeData(JSON.parse(fs.readFileSync(INITIAL_DATA_FILE, "utf8"))) : defaults; const data = loadData(); const categoryMap = new Map<string, string>(); const categories = original.categories.filter((item: AnyData) => item.type === "live").map((item: AnyData) => { const next = { ...item, id: uid() }; categoryMap.set(item.id, next.id); return next; }); data.categories = data.categories.filter((item: AnyData) => item.type !== "live").concat(categories); data.streams = original.streams.map((item: AnyData) => ({ ...item, id: uid(), categoryId: categoryMap.get(item.categoryId) || item.categoryId })); await saveData(data); res.json({ ok: true, total: data.streams.length }); });
app.post("/api/sync-bundled-catalog", requireAdmin, async (_req, res) => { const original = fs.existsSync(INITIAL_DATA_FILE) ? normalizeData(JSON.parse(fs.readFileSync(INITIAL_DATA_FILE, "utf8"))) : defaults; const data = loadData(); const categories = new Map<string, AnyData>(data.categories.filter((item: AnyData) => item.type === "live").map((item: AnyData) => [String(item.name).toLowerCase(), item])); const categoryMap = new Map<string, string>(); for (const item of original.categories.filter((item: AnyData) => item.type === "live")) { let category: AnyData | undefined = categories.get(String(item.name).toLowerCase()); if (!category) { const created: AnyData = { ...item, id: uid() }; data.categories.push(created); categories.set(String(item.name).toLowerCase(), created); category = created; } if (!category) continue; categoryMap.set(item.id, category.id); } const urls = new Set(data.streams.map((item: AnyData) => item.url)); let added = 0; for (const item of original.streams) if (item.url && !urls.has(item.url)) { data.streams.push({ ...item, id: uid(), categoryId: categoryMap.get(item.categoryId) || item.categoryId }); urls.add(item.url); added++; } await saveData(data); res.json({ ok: true, added, total: data.streams.length }); });

app.get("/api/admin/plans", requireAdmin, (_req, res) => res.json({ plans: loadData().plans }));
app.patch("/api/admin/plans/:code", requireAdmin, async (req, res) => { const data = loadData(); const plan = planByCode(data, req.params.code); if (!plan) return res.status(404).json({ error: "الباقة غير موجودة" }); if ("price" in req.body) plan.price = Math.max(0, Number(req.body.price) || 0); if ("originalPrice" in req.body) plan.originalPrice = req.body.originalPrice === null || req.body.originalPrice === "" ? null : Math.max(0, Number(req.body.originalPrice) || 0); if ("name" in req.body) plan.name = String(req.body.name || plan.name); if ("durationDays" in req.body) plan.durationDays = Math.max(1, Number(req.body.durationDays) || plan.durationDays); await saveData(data); res.json({ ok: true, plan }); });
app.get("/api/public/catalog", requireViewer, (_req, res) => { const data = loadData(); res.json({ categories: data.categories.filter((item: AnyData) => item.type === "live"), streams: data.streams.map((item: AnyData, index: number) => ({ id: item.id, num: index + 1, name: item.name, categoryId: item.categoryId, logo: item.streamIcon || item.logo || "", extension: item.containerExtension || "m3u8" })) }); });
app.get("/api/public/stream/:id", requireViewer, (req, res) => { const stream = loadData().streams.find((item: AnyData) => item.id === req.params.id); if (!stream) return res.status(404).json({ error: "القناة غير موجودة" }); if (!/^https?:\/\//i.test(stream.url)) return res.status(400).json({ error: "رابط البث غير صالح" }); res.json({ id: stream.id, name: stream.name, url: stream.url, extension: stream.containerExtension || "m3u8" }); });

app.post("/api/import-m3u", requireAdmin, async (req, res) => { let content = String(req.body?.content || ""); if (!content && req.body?.url) { const response = await fetch(String(req.body.url), { signal: AbortSignal.timeout(15000) }); if (!response.ok) return res.status(502).json({ error: `تعذر تحميل رابط M3U: HTTP ${response.status}` }); content = await response.text(); } if (!content) return res.status(400).json({ error: "الصق محتوى M3U أو اكتب رابط القائمة" }); const data = loadData(); if (req.body?.replace) { data.streams = []; data.categories = data.categories.filter((item: AnyData) => item.type !== "live"); } const categoryCache = new Map(data.categories.filter((item: AnyData) => item.type === "live").map((item: AnyData) => [item.name, item.id])); const getCategory = (name: string) => { const label = name.trim() || "Live"; if (categoryCache.has(label)) return categoryCache.get(label)!; const category = { id: uid(), name: label, type: "live" }; data.categories.push(category); categoryCache.set(label, category.id); return category.id; }; let meta: AnyData | null = null; let imported = 0; for (const rawLine of content.split(/\r?\n/)) { const line = rawLine.trim(); if (/^#EXTINF\s*:/i.test(line)) { const comma = line.search(/[,،]/); const attrs = (key: string) => line.match(new RegExp(`${key}=\"([^\"]*)\"`, "i"))?.[1] || ""; meta = { name: comma >= 0 ? line.slice(comma + 1).trim() : "Channel", logo: attrs("tvg-logo"), group: attrs("group-title") || "Live" }; } else if (line && !line.startsWith("#") && meta) { data.streams.push({ id: uid(), name: meta.name, url: line, categoryId: getCategory(meta.group), logo: meta.logo, streamIcon: meta.logo, containerExtension: /\.m3u8(?:\?|$)/i.test(line) ? "m3u8" : "ts" }); meta = null; imported++; } } await saveData(data); res.json({ ok: true, imported }); });

app.get("/player_api.php", (req, res) => { const username = String(req.query.username || ""); const password = String(req.query.password || ""); const data = loadData(); const user = findUser(data, username, password); if (!req.query.action) return res.json(xtreamResponse(user, password, req)); if (!user || !userActive(user)) return res.json([]); const action = String(req.query.action); if (action === "get_live_categories") return res.json(data.categories.filter((item: AnyData) => item.type === "live").map((item: AnyData) => ({ category_id: item.id, category_name: item.name, parent_id: 0 }))); if (action === "get_live_streams") return res.json(data.streams.map((item: AnyData, index: number) => ({ num: index + 1, name: item.name, stream_type: "live", stream_id: item.id, stream_icon: item.streamIcon || item.logo || "", category_id: item.categoryId, direct_source: item.url, tv_archive: 0 }))); return res.json([]); });
app.get("/get.php", (req, res) => { const username = String(req.query.username || ""); const password = String(req.query.password || ""); const data = loadData(); const user = findUser(data, username, password); if (!user || !userActive(user)) return res.status(401).send("#EXTM3U\n# Invalid credentials\n"); const body = ["#EXTM3U", ...data.streams.map((item: AnyData) => `#EXTINF:-1 tvg-logo=\"${item.streamIcon || item.logo || ""}\" group-title=\"${item.categoryId || "Live"}\",${item.name}\n${item.url}`)].join("\n"); res.type("audio/x-mpegurl").send(`${body}\n`); });

app.use(express.static(PUBLIC_DIR, { extensions: ["html"] }));
app.get("/admin", (_req, res) => res.sendFile(path.join(PUBLIC_DIR, "admin.html")));
app.get("*", (req, res, next) => { if (req.path.startsWith("/api/") || req.path.includes(".php")) return next(); res.sendFile(path.join(PUBLIC_DIR, "index.html")); });
app.use((error: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => { console.error(error); res.status(500).json({ error: "حدث خطأ داخلي" }); });

app.listen(PORT, "0.0.0.0", () => console.log(`SHEPO server ready on port ${PORT}`));
