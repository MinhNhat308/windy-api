import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from './app.mjs';
import { hashPassword, hashToken } from './security.mjs';
test('HTTP authentication/role boundary and logout (fake database, not Atlas)', async () => {
  const users = [{_id:'collab',username:'tester',role:'collaborator',active:true,password_hash:await hashPassword('test-password-only')}];
  const sessions = new Map();
  const db = {
    command: async () => ({ok:1}),
    collection(name) { return {
      findOne: async query => {
        if (name === 'users') return users.find(u => (!query.username || u.username === query.username) && (!query._id || u._id === query._id) && (query.active === undefined || u.active === query.active));
        if (name === 'sessions') { const s = sessions.get(query._id); return s && s.expires_at > query.expires_at.$gt ? s : null; }
      },
      findOneAndUpdate: async () => ({count:1}),
      insertOne: async row => { if (name === 'sessions') sessions.set(row._id,row); },
      deleteOne: async query => sessions.delete(query._id),
    }; },
  };
  const app = await createApp(db); const server = app.listen(0,'127.0.0.1');
  await new Promise(resolve => server.once('listening',resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = (path,body,token,method=body ? 'POST' : 'GET') => fetch(base+path,{method,headers:{'Content-Type':'application/json',...(token?{Authorization:`Bearer ${token}`}:{})},body:body?JSON.stringify(body):undefined});
  try {
    assert.equal((await call('/health')).status,200);
    assert.equal((await call('/auth/me')).status,401);
    assert.equal((await call('/auth/login',{username:'tester',password:'wrong'})).status,401);
    const login = await call('/auth/login',{username:'tester',password:'test-password-only'}); assert.equal(login.status,200);
    const {token,member} = await login.json(); assert.equal(member.password_hash,undefined); assert.ok(sessions.has(hashToken(token)));
    assert.equal((await call('/auth/me',null,token)).status,200);
    assert.equal((await call('/data/windy_batches',{name:'blocked',planned_date:null},token)).status,403);
    assert.equal((await call('/data/users',null,token)).status,404);
    assert.equal((await call('/auth/me',null,'forged')).status,401);
    users[0].active=false; assert.equal((await call('/auth/me',null,token)).status,401); users[0].active=true;
    assert.equal((await call('/auth/logout',{},token)).status,200);
    assert.equal((await call('/auth/me',null,token)).status,401);
  } finally { await new Promise(resolve => server.close(resolve)); }
});
