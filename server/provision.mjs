import { randomUUID } from 'node:crypto';
import { connect } from './database.mjs';
import { hashPassword } from './security.mjs';
let client;
try {
  const password = process.env.WINDY_INITIAL_PASSWORD;
  if (!password || password.length < 8 || password.length > 256) throw new Error('Set WINDY_INITIAL_PASSWORD locally (8–256 characters)');
  const connection = await connect(); client = connection.client;
  for (const [username, role] of [['admin','admin'],['dangpk3','collaborator'],['lambn','collaborator']]) {
    const collection = connection.db.collection('users');
    const existing = await collection.findOne({ username });
    if (existing) {
      if (existing.role !== role) throw new Error('Existing role mismatch; review database privately');
      console.log(`${username}: already exists, unchanged`); continue;
    }
    await collection.insertOne({ _id: randomUUID(), username, role, active: true, password_hash: await hashPassword(password) });
    console.log(`${username}: created (${role})`);
  }
} catch { console.error('Provisioning incomplete. Check masked inputs, DB access and existing roles. No credentials logged, no users deleted.'); process.exitCode = 1; }
finally { await client?.close(); }
