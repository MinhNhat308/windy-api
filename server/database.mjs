import { MongoClient } from 'mongodb';
export async function connect() {
  const uri = process.env.MONGODB_URI;
  if (!uri || /<db_password>/.test(uri)) throw new Error('Configure MONGODB_URI securely on the server');
  // Never disable TLS certificate validation or print the credential-bearing URI.
  const client = new MongoClient(uri, { tls: true, serverSelectionTimeoutMS: 10000, maxPoolSize: 10 });
  await client.connect();
  const db = client.db(process.env.MONGODB_DB || 'windy');
  await Promise.all([
    db.collection('users').createIndex({ username: 1 }, { unique: true }),
    db.collection('sessions').createIndex({ expires_at: 1 }, { expireAfterSeconds: 0 }),
    db.collection('login_limits').createIndex({ expires_at: 1 }, { expireAfterSeconds: 0 }),
    db.collection('windy_phases').createIndex({ batch_id: 1, position: 1 }, { unique: true }),
    db.collection('windy_items').createIndex({ phase_id: 1, jira_key: 1 }, { unique: true }),
  ]);
  return { client, db };
}
