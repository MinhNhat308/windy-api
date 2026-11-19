import { connect } from './database.mjs';
import { createApp } from './app.mjs';
import { startupDiagnostic } from './diagnostics.mjs';
try {
  const { db, client } = await connect();
  const app = await createApp(db, { origins: (process.env.ALLOWED_ORIGINS || '').split(',').filter(Boolean) });
  const server = app.listen(Number(process.env.PORT || 10000), '0.0.0.0', () => console.log('Windy API listening'));
  process.on('SIGTERM', () => { server.close(async () => { await client.close(); process.exit(0); }); });
} catch (error) { console.error(`Windy API startup failed. ${startupDiagnostic(error)}`); process.exitCode = 1; }
