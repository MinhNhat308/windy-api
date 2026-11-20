import { randomBytes, scrypt as callback, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';
import { z } from 'zod';
const scrypt = promisify(callback);
export const username = z.string().trim().toLowerCase().regex(/^[a-z0-9_]{3,32}$/);
export const loginSchema = z.object({ username, password: z.string().min(1).max(256) }).strict();
const id = z.string().uuid();
export const phaseScheduleSchema = z.object({ planned_date: z.iso.date().nullable() }).strict();
export const windyRoles = ['admin','dev','pm','tester','collaborator'];
export const testHandleRoles = windyRoles.filter(role => role !== 'dev');
export const assignmentSchema = z.object({ user_id: id.nullable(), version: id.nullable() }).strict();
export const devWorkSchema = z.object({ version: id, status: z.enum(['PENDING','IN_PROGRESS']), note: z.string().trim().max(4000) }).strict();
export const jiraIsComplete = row => row?.jira_completed ?? /^(resolved|closed|done|completed)$/i.test(row?.jira_status?.trim() ?? '');
export const testWorkSchema = z.object({ version: id, status: z.enum(['PENDING','PASSED','FAIL']), note: z.string().trim().max(4000).default('') }).strict().refine(v => v.status !== 'FAIL' || v.note, { message: 'Fail requires a reason' });
export const schemas = {
  windy_batches: z.object({ name: z.string().trim().min(1).max(100), planned_date: z.iso.date().nullable(), notes: z.string().max(10000).default('') }).strict(),
  windy_phases: z.object({ batch_id: id, name: z.string().trim().min(1).max(150), position: z.number().int().nonnegative() }).strict(),
  windy_items: z.object({ phase_id: id, jira_key: z.string().regex(/^[A-Z][A-Z0-9_]*-[0-9]+$/) }).strict(),
  windy_hotfixes: z.object({ id, title: z.string().trim().min(1).max(500), notes: z.string().max(20000), build: z.string().max(100), status: z.enum(['OPEN','FIXING','FIXED']), revisions: z.array(z.number().int().positive().safe()).max(500), updated_at: z.string().optional() }).strict(),
};
export const resources = new Set([...Object.keys(schemas), 'windy_jira_snapshots', 'windy_progress']);
export function hashToken(value) { return createHash('sha256').update(value).digest('hex'); }
export async function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const hash = await scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return `${salt}:${hash.toString('hex')}`;
}
export async function checkPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const actual = await scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 });
  const expected = Buffer.from(hash, 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
export function publicMember(user) { return { user_id: user._id, username: user.username, role: user.role, active: user.active, must_change_password: user.must_change_password === true }; }
export function canDevelop(user) { return user.role === 'admin' || user.role === 'dev'; }
export function allowHotfix(user, input, old) {
  if (canDevelop(user)) return true;
  if (old && old.created_by !== user._id) return false;
  return input.status === (old?.status ?? 'OPEN') && JSON.stringify(input.revisions) === JSON.stringify(old?.revisions ?? []);
}
