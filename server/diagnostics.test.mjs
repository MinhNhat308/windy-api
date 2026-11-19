import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startupDiagnostic } from './diagnostics.mjs';
test('startup diagnostics classify failures without leaking URI or secrets', () => {
  for (const error of [
    {code:18,message:'bad auth secret-password'},
    {code:13,message:'not authorized secret-password'},
    {name:'MongoServerSelectionError',message:'mongodb://user:secret-password@host'},
    {name:'MongoParseError',message:'mongodb://user:secret-password@host'},
    {message:'unknown secret-password'},
  ]) {
    const result = startupDiagnostic(error);
    assert.ok(!result.includes('secret-password')); assert.ok(!result.includes('mongodb://'));
  }
  assert.match(startupDiagnostic({message:'Configure MONGODB_URI securely on the server'}),/CONFIG_MONGODB_URI/);
  assert.match(startupDiagnostic({code:18}),/DB_AUTH/);
  assert.match(startupDiagnostic({name:'MongoServerSelectionError'}),/DB_NETWORK/);
});
