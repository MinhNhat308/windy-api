import { randomUUID } from 'node:crypto';
import { connect } from './database.mjs';
import { hashPassword } from './security.mjs';
import { startupDiagnostic } from './diagnostics.mjs';
let client;
try {
  const [mode, ...extra] = process.argv.slice(2);
  if (extra.length || (mode && mode !== '--dev-team')) throw Object.assign(new Error(), { code: 'PROVISION_MODE' });
  const accounts = mode === '--dev-team' ? [['namdt54','dev'],['phuocnh19','dev']] : [['admin','admin'],['dangpk3','collaborator'],['lambn','collaborator']];
  const password = process.env.WINDY_INITIAL_PASSWORD;
  if (!password || password.length < 8 || password.length > 256) throw Object.assign(new Error(), { code: 'PROVISION_PASSWORD_LENGTH' });
  const connection = await connect(); client = connection.client;
  for (const [username, role] of accounts) {
    const collection = connection.db.collection('users');
    const existing = await collection.findOne({ username });
    if (existing) {
      if (existing.role !== role || existing.active !== true) {
        console.error(`${username}: existing account is inactive or has a different role; unchanged`);
        process.exitCode = 1;
        continue;
      }
      console.log(`${username}: already exists, unchanged`); continue;
    }
    await collection.insertOne({ _id: randomUUID(), username, role, active: true, password_hash: await hashPassword(password), ...(mode === '--dev-team' ? { must_change_password: true } : {}) });
    console.log(`${username}: created (${role})`);
  }
} catch (error) {
  console.error(error.code === 'PROVISION_MODE' ? 'PROVISION_MODE: Unknown provisioning mode.'
    : error.code === 'PROVISION_PASSWORD_LENGTH' ? 'PROVISION_PASSWORD_LENGTH: Enter a Windy password of 8–256 characters.'
    : error.code === 11000 ? 'PROVISION_DUPLICATE: An account already exists. Verify the account and role before retrying.'
    : startupDiagnostic(error, { local: true }));
  process.exitCode = 1;
}
finally { await client?.close(); }
