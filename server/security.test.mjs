import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hashPassword, checkPassword, hashToken, allowHotfix, schemas, loginSchema, publicMember } from './security.mjs';
test('salted password hashes verify without plaintext storage', async () => {
  const a = await hashPassword('test-password-only'); const b = await hashPassword('test-password-only');
  assert.notEqual(a,b); assert.equal(await checkPassword('test-password-only',a),true); assert.equal(await checkPassword('wrong',a),false);
});
test('collaborators cannot spoof fix state/revisions or edit another note', () => {
  const user = { _id:'one', role:'collaborator' }; const input = { status:'OPEN', revisions:[] };
  assert.equal(allowHotfix(user,input,null),true);
  assert.equal(allowHotfix(user,{...input,status:'FIXED'},null),false);
  assert.equal(allowHotfix(user,{...input,revisions:[1]},null),false);
  assert.equal(allowHotfix(user,input,{...input,created_by:'two'}),false);
  assert.equal(allowHotfix(user,input,{...input,created_by:'one'}),true);
  assert.equal(allowHotfix({role:'dev'}, {...input,status:'FIXED'},null),true);
});
test('strict schemas reject mass assignment and query injection', () => {
  assert.equal(loginSchema.safeParse({ username:{$ne:null},password:'x' }).success,false);
  assert.equal(schemas.windy_batches.safeParse({name:'v154',planned_date:null,role:'admin'}).success,false);
  assert.equal(loginSchema.parse({username:' ADMIN ',password:'x'}).username,'admin');
});
test('tokens are hashed and members expose no secrets', () => {
  assert.equal(hashToken('a').length,64);
  assert.deepEqual(publicMember({_id:'u', username:'tester',role:'collaborator',active:true,password_hash:'secret',credential_version:'private'}),{user_id:'u',username:'tester',role:'collaborator',active:true,must_change_password:false});
});
