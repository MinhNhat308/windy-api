import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { rateLimit } from 'express-rate-limit';
import { randomBytes, randomUUID } from 'node:crypto';
import { z } from 'zod';
import { allowHotfix, checkPassword, hashPassword, hashToken, loginSchema, phaseScheduleSchema, schemas, resources, publicMember } from './security.mjs';

export async function createApp(db, { origins = [], production = true } = {}) {
  const app = express();
  app.disable('x-powered-by');
  // Render terminates HTTPS and adds one reverse proxy hop.
  app.set('trust proxy', 1);
  app.use(helmet());
  app.use(cors({ origin(origin, done) { done(null, !origin || origins.includes(origin)); }, allowedHeaders: ['Content-Type','Authorization'], methods: ['GET','POST','PUT','OPTIONS'] }));
  app.use(express.json({ limit: '128kb' }));
  app.use((_req,res,next) => { res.set('Cache-Control','no-store'); next(); });
  app.get('/health', async (_req,res) => {
    try { await db.command({ ping: 1 }); res.json({ ok: true }); } catch { res.status(503).json({ error: 'Database unavailable' }); }
  });
  app.use(rateLimit({ windowMs: 60000, limit: 180, standardHeaders: 'draft-8', legacyHeaders: false }));
  const dummyHash = await hashPassword(randomBytes(32).toString('hex'));
  function fail(res, status, message) { return res.status(status).json({ error: message }); }
  app.post('/auth/login', async (req,res) => {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) return fail(res,400,'Invalid login');
    const { username, password } = parsed.data;
    // Persistent limits survive Render restarts and apply across instances.
    const window = Math.floor(Date.now() / 900000);
    for (const scope of [`ip:${req.ip}`, `user:${username}`]) {
      const result = await db.collection('login_limits').findOneAndUpdate(
        { _id: hashToken(`${scope}:${window}`) },
        { $inc: { count: 1 }, $setOnInsert: { expires_at: new Date((window + 2) * 900000) } },
        { upsert: true, returnDocument: 'after' });
      if (result.count > (scope.startsWith('ip:') ? 60 : 15)) return fail(res,429,'Too many attempts. Try again later.');
    }
    const user = await db.collection('users').findOne({ username });
    const valid = await checkPassword(password, user?.password_hash ?? dummyHash);
    if (!valid || !user?.active) return fail(res,401,'Invalid login');
    const token = randomBytes(32).toString('base64url');
    const expires = new Date(Date.now() + 8 * 3600000);
    await db.collection('sessions').insertOne({ _id: hashToken(token), user_id: user._id, expires_at: expires });
    res.json({ token, member: publicMember(user), expires_at: expires.toISOString() });
  });
  app.use(async (req,res,next) => {
    const token = req.headers.authorization?.match(/^Bearer ([A-Za-z0-9_-]{43})$/)?.[1];
    if (!token) return fail(res,401,'Login required');
    const session = await db.collection('sessions').findOne({ _id: hashToken(token), expires_at: { $gt: new Date() } });
    const user = session && await db.collection('users').findOne({ _id: session.user_id, active: true });
    if (!user || !['admin','dev','collaborator'].includes(user.role)) return fail(res,401,'Session expired or account disabled');
    req.user = user; req.sessionId = session._id; next();
  });
  app.get('/auth/me', (req,res) => res.json(publicMember(req.user)));
  app.post('/auth/logout', async (req,res) => { await db.collection('sessions').deleteOne({ _id: req.sessionId }); res.json({ ok: true }); });
  app.post('/auth/password', async (req,res) => {
    const result = z.object({ current: z.string().min(1).max(256), password: z.string().min(12).max(256) }).strict().safeParse(req.body);
    if (!result.success) return fail(res,400,'New password must be at least 12 characters');
    if (!await checkPassword(result.data.current,req.user.password_hash)) return fail(res,403,'Current password incorrect');
    await db.collection('users').updateOne({ _id: req.user._id, password_hash: req.user.password_hash }, { $set: { password_hash: await hashPassword(result.data.password) } });
    await db.collection('sessions').deleteMany({ user_id: req.user._id });
    res.json({ ok: true });
  });
  app.get('/data/:resource', async (req,res) => {
    if (!resources.has(req.params.resource)) return fail(res,404,'Not found');
    const offset = Number(req.query.offset ?? 0);
    if (!Number.isSafeInteger(offset) || offset < 0 || offset > 1000000) return fail(res,400,'Invalid offset');
    const rows = await db.collection(req.params.resource).find({}, { projection: { _id: 0 } }).sort({ id: 1 }).skip(offset).limit(500).toArray();
    res.json(rows);
  });
  app.post('/data/:resource', async (req,res) => {
    const resource = req.params.resource;
    if (!['windy_batches','windy_phases','windy_items'].includes(resource)) return fail(res,404,'Not found');
    if (resource !== 'windy_items' && req.user.role !== 'admin') return fail(res,403,'Admin required');
    const values = z.array(schemas[resource]).min(1).max(resource === 'windy_items' ? 200 : 1).parse(Array.isArray(req.body) ? req.body : [req.body]);
    const parentIds = [...new Set(values.map(v => resource === 'windy_items' ? v.phase_id : v.batch_id).filter(Boolean))];
    if (parentIds.length && await db.collection(resource === 'windy_items' ? 'windy_phases' : 'windy_batches').countDocuments({ id: { $in: parentIds } }) !== parentIds.length) return fail(res,400,'Parent not found');
    const now = new Date().toISOString();
    if (resource === 'windy_items') {
      // Idempotent per phase/key: retry cannot duplicate or overwrite original submitter.
      await db.collection(resource).bulkWrite(values.map(value => ({ updateOne: { filter: { phase_id: value.phase_id, jira_key: value.jira_key }, update: { $setOnInsert: { ...value, id: randomUUID(), submitted_by: req.user._id, created_at: now } }, upsert: true } })));
    } else await db.collection(resource).insertOne({ ...values[0], id: randomUUID(), created_by: req.user._id, created_at: now });
    res.status(201).json({ ok: true });
  });
  app.put('/phases/:id/schedule', async (req,res) => {
    if (req.user.role !== 'admin') return fail(res,403,'Admin required');
    const id = z.string().uuid().parse(req.params.id);
    const { planned_date } = phaseScheduleSchema.parse(req.body);
    const result = await db.collection('windy_phases').updateOne({ id }, { $set: { planned_date } });
    if (!result.matchedCount) return fail(res,404,'Phase not found');
    res.json({ planned_date });
  });
  app.put('/hotfixes/:id', async (req,res) => {
    const input = schemas.windy_hotfixes.parse(req.body);
    if (input.id !== req.params.id) return fail(res,400,'ID mismatch');
    const collection = db.collection('windy_hotfixes');
    const old = await collection.findOne({ _id: input.id });
    if (!allowHotfix(req.user,input,old)) return fail(res,403,'Only developers may change fix status/commits; collaborators edit only their own notes');
    const { updated_at: expected, ...fields } = input;
    const now = new Date().toISOString();
    if (old) {
      if (expected !== old.updated_at) return fail(res,409,'Note changed. Refresh and review before saving.');
      const result = await collection.updateOne({ _id: input.id, updated_at: expected }, { $set: { ...fields, updated_at: now } });
      if (!result.matchedCount) return fail(res,409,'Note changed. Refresh before saving.');
    } else await collection.insertOne({ _id: input.id, ...fields, updated_at: now, created_by: req.user._id });
    res.json({ ok: true });
  });
  app.use((_req,res) => fail(res,404,'Not found'));
  app.use((error,_req,res,_next) => {
    // Do not send/log exception details, Mongo URI, request bodies or bearer tokens.
    if (error instanceof z.ZodError || error.type === 'entity.parse.failed') return fail(res,400,'Invalid request');
    if (error.code === 11000) return fail(res,409,'Duplicate entry. Refresh before retrying.');
    if (error.type === 'entity.too.large') return fail(res,413,'Request too large');
    fail(res,503,production ? 'Service unavailable; refresh before retrying a write' : 'Service unavailable');
  });
  return app;
}
