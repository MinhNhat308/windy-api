import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from './app.mjs';
import { hashPassword, hashToken } from './security.mjs';
test('HTTP authentication/role boundary and logout (fake database, not Atlas)', async () => {
  const users = [{_id:'collab',username:'tester',role:'collaborator',active:true,password_hash:await hashPassword('test-password-only')},
    {_id:'dev',username:'new_dev',role:'dev',active:true,password_hash:await hashPassword('temp-test-only'),must_change_password:true},
    {_id:'admin',username:'admin',role:'admin',active:true,password_hash:await hashPassword('admin-test-password')}];
  const sessions = new Map();
  const phaseId = '9ab5e8ad-46e5-4707-86da-cc98c1c50905';
  const phase = { id: phaseId, position: 0 };
  const itemId = 'dab5e8ad-46e5-4707-86da-cc98c1c50905';
  const item = { id:itemId, phase_id:phaseId, jira_key:'TEST-1', submitted_by:'collab' };
  const pmId = '11b5e8ad-46e5-4707-86da-cc98c1c50905';
  const devId = '22b5e8ad-46e5-4707-86da-cc98c1c50905';
  const testerId = '33b5e8ad-46e5-4707-86da-cc98c1c50905';
  const memberToken = id => {
    const token = id.replaceAll('-', '').padEnd(43,'x');
    sessions.set(hashToken(token),{_id:hashToken(token),user_id:id,expires_at:new Date(Date.now()+60000)});
    return token;
  };
  const roles = [['_pm',pmId,'pm'],['_dev',devId,'dev'],['_tester',testerId,'tester']];
  for (const [username,_id,role] of roles) users.push({username,_id,role,active:true});
  const property = (row, key) => key.split('.').reduce((value, part) => value?.[part], row);
  const matches = (row, query) => Object.entries(query).every(([key, expected]) => {
    const value = property(row,key);
    if (expected?.$in) return expected.$in.includes(value);
    if (expected?.$exists !== undefined) return (value !== undefined) === expected.$exists;
    return expected === null ? value == null : value === expected;
  });
  let snapshot;
  const db = {
    command: async () => ({ok:1}),
    collection(name) { return {
      findOne: async query => {
         if (name === 'users') return users.find(u => matches(u,query));
         if (name === 'sessions') { const s = sessions.get(query._id); return s && s.expires_at > query.expires_at.$gt ? s : null; }
          if (name === 'windy_items' && matches(item,query)) return item;
       },
       find: query => ({sort: () => ({toArray: async () => users.filter(u => matches(u,query))})}),
      findOneAndUpdate: async () => ({count:1}),
      insertOne: async row => { if (name === 'sessions') sessions.set(row._id,row); },
      distinct: async (field, filter) => name === 'windy_items' && field === 'jira_key' && !item.removed_at && filter.jira_key.$in.includes(item.jira_key) ? [item.jira_key] : [],
      bulkWrite: async operations => { assert.equal(name,'windy_jira_snapshots'); snapshot = operations[0].updateOne.update.$set; },
        updateOne: async (filter, { $set, $unset }) => {
         const {id, _id, password_hash, active} = filter;
         if (name === 'users') {
           const user = users.find(u => u._id === _id && u.active === active && u.password_hash === password_hash);
           if (!user) return { matchedCount: 0 };
           Object.assign(user, $set); return { matchedCount: 1 };
         }
        if (name === 'windy_items') {
           if (!matches(item,filter)) return {matchedCount:0};
           for (const [key,value] of Object.entries($set ?? {})) {
             const [field, subfield] = key.split('.');
             if (subfield) item[field][subfield] = value; else item[field] = value;
           }
           for (const key of Object.keys($unset ?? {})) delete item[key];
           return {matchedCount:1};
        }
        assert.equal(name, 'windy_phases');
        if (id !== phaseId) return {matchedCount:0};
        Object.assign(phase,$set); return {matchedCount:1};
      },
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
    const schedule = `/phases/${phaseId}/schedule`;
    assert.equal((await call(schedule,{planned_date:'2026-11-19'},token,'PUT')).status,403);
    const admin = await (await call('/auth/login',{username:'admin',password:'admin-test-password'})).json();
    assert.equal((await call(schedule,{planned_date:'2026-02-30'},admin.token,'PUT')).status,400);
    assert.equal((await call(schedule,{planned_date:'2026-11-19',position:3},admin.token,'PUT')).status,400);
    assert.equal((await call(schedule,{planned_date:'2026-11-19'},admin.token,'PUT')).status,200);
    assert.deepEqual(phase,{id:phaseId,position:0,planned_date:'2026-11-19'});
    assert.equal((await call(schedule,{planned_date:null},admin.token,'PUT')).status,200);
    assert.equal(phase.planned_date,null);
    const rows = [{jira_key:'TEST-1',summary:'Test title',jira_status:'Open'}];
    assert.equal((await call('/calendar/jira-snapshots',rows,token,'PUT')).status,403);
    assert.equal((await call('/calendar/jira-snapshots',[{...rows[0],description:'private'}],admin.token,'PUT')).status,400);
    assert.equal((await call('/calendar/jira-snapshots',rows,admin.token,'PUT')).status,200);
    assert.equal(snapshot.summary,'Test title');
    const itemPath = `/calendar/items/${itemId}`;
    const pm = memberToken(pmId), dev = memberToken(devId), tester = memberToken(testerId);
    const put = (path, body, token) => call(path,body,token,'PUT');
    assert.equal((await call('/calendar/people',null,dev)).status,403);
    const directory = await (await call('/calendar/people',null,pm)).json();
    assert.ok(directory.some(p => p.user_id === devId));
    assert.ok(directory.every(p => ['admin','tester','dev'].includes(p.role) && !('password_hash' in p)));
    assert.equal((await put(`${itemPath}/dev/assign`,{user_id:devId,version:null},dev)).status,403);
    assert.equal((await put(`${itemPath}/dev/assign`,{user_id:testerId,version:null},pm)).status,400);
    assert.equal((await put(`${itemPath}/dev/assign`,{user_id:devId,version:null},pm)).status,200);
    assert.equal((await put(`${itemPath}/test/assign`,{user_id:testerId,version:null},admin.token)).status,200);
    const version = item.test_handle.version;
    assert.equal((await put(`${itemPath}/test/result`,{version,status:'FAIL',note:'  '},tester)).status,400);
    assert.equal((await put(`${itemPath}/test/result`,{version,status:'PASSED',note:''},tester)).status,200);
    assert.equal((await put(`${itemPath}/test/result`,{version,status:'FAIL',note:'Stale'},tester)).status,409);
    assert.equal((await put(`${itemPath}/dev/result`,{version:item.dev_handle.version,status:'DONE',note:''},dev)).status,200);
    assert.equal((await put(`${itemPath}/dev/assign`,{user_id:null,version:item.dev_handle.version},pm)).status,200);
    assert.equal(item.dev_handle,undefined);
    item.submitted_by = 'other';
    assert.equal((await call(itemPath,null,token,'DELETE')).status,404);
    item.submitted_by = 'collab';
    assert.equal((await call(itemPath,null,token,'DELETE')).status,200);
    assert.equal(item.removed_by,'collab');
    assert.equal(item.jira_key,'TEST-1');
    assert.equal((await call('/calendar/jira-snapshots',rows,admin.token,'PUT')).status,409);
    assert.equal((await call('/data/users',null,token)).status,404);
    assert.equal((await call('/auth/me',null,'forged')).status,401);
    users[0].active=false; assert.equal((await call('/auth/me',null,token)).status,401); users[0].active=true;
    assert.equal((await call('/auth/logout',{},token)).status,200);
    assert.equal((await call('/auth/me',null,token)).status,401);
    const temp = {username:'new_dev',password:'temp-test-only'};
    const newPassword = 'unique-new-test-password';
    const first = await (await call('/auth/login',temp)).json();
    const second = await (await call('/auth/login',temp)).json();
    assert.equal(first.member.must_change_password,true);
    assert.equal((await (await call('/auth/me',null,first.token)).json()).must_change_password,true);
    assert.equal((await call('/data/windy_items',null,first.token)).status,403);
    assert.equal((await call('/auth/password',{current:temp.password,password:newPassword})).status,401);
    assert.equal((await call('/auth/password',{current:'wrong',password:newPassword},first.token)).status,403);
    assert.equal((await call('/auth/password',{current:temp.password,password:'short'},first.token)).status,400);
    assert.equal((await call('/auth/password',{current:temp.password,password:temp.password},first.token)).status,400);
    assert.equal((await call('/auth/password',{current:temp.password,password:newPassword},first.token)).status,200);
    assert.equal((await call('/auth/me',null,first.token)).status,401);
    assert.equal((await call('/auth/me',null,second.token)).status,401);
    assert.equal((await call('/auth/login',temp)).status,401);
    const changed = await (await call('/auth/login',{...temp,password:newPassword})).json();
    assert.equal(changed.member.must_change_password,false);
    assert.equal((await call('/auth/me',null,changed.token)).status,200);
    assert.equal((await call('/data/windy_items',{phase_id:phaseId,jira_key:'TEST-2'},changed.token)).status,403);
    assert.equal((await call(itemPath,null,changed.token,'DELETE')).status,403);
    assert.equal((await call(schedule,{planned_date:null},changed.token,'PUT')).status,403);
    assert.equal((await call('/hotfixes/example',{},changed.token,'PUT')).status,403);
    const resolvePath = `/calendar/jira/${item.jira_key}/resolve-access`;
    assert.equal((await call(resolvePath,null,changed.token)).status,403);
    delete item.removed_at;
    item.dev_handle = {user_id:'dev'};
    assert.equal((await call(resolvePath,null,changed.token)).status,200);
    assert.equal((await call('/calendar/jira/TEST-2/resolve-access',null,changed.token)).status,403);
    assert.equal((await call('/calendar/jira/TEST-2/resolve-access',null,admin.token)).status,200);
    item.dev_handle.user_id = 'other';
    assert.equal((await call(resolvePath,null,changed.token)).status,403);
  } finally { await new Promise(resolve => server.close(resolve)); }
});
