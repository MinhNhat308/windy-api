// Never return raw exception messages: drivers may include credentials or hosts.
export function startupDiagnostic(error, { local = false } = {}) {
  const message = String(error?.message ?? '');
  if (message.includes('Configure MONGODB_URI')) return local ? 'CONFIG_MONGODB_URI: Enter the Atlas Drivers URI with the password placeholder replaced in the hidden prompt.' : 'CONFIG_MONGODB_URI: Missing URI or unchanged password placeholder. Set MONGODB_URI in Render Environment.';
  if (error?.code === 18 || /authentication failed|bad auth/i.test(message)) return 'DB_AUTH: Atlas rejected authentication. Check database user/password, authSource, and URL-encoding.';
  if (error?.code === 13 || /not authorized/i.test(message)) return 'DB_PERMISSION: Atlas user lacks required permissions. Grant readWrite on the configured Windy database.';
  if (error?.name === 'MongoParseError' || error?.name === 'MongoInvalidArgumentError') return 'DB_URI_FORMAT: Invalid MongoDB URI/options. Use Atlas Connect > Drivers and URL-encode the password.';
  if (/ENOTFOUND|querySrv|queryTxt|EAI_AGAIN/i.test(message)) return 'DB_DNS: Cannot resolve Atlas DNS. Check the driver URI and cluster availability.';
  if (/certificate|TLS|SSL/i.test(message)) return 'DB_TLS: TLS connection failed. Check Atlas connectivity; do not disable certificate validation.';
  if (error?.name === 'MongoServerSelectionError' || /ETIMEDOUT|ECONNREFUSED/i.test(message)) return local ? 'DB_NETWORK: Cannot reach Atlas. Check that Atlas Network Access allows this machine’s current public IP, and that the cluster is running.' : 'DB_NETWORK: Cannot select an Atlas server. Check Atlas Network Access against Render outbound IP ranges, cluster availability, and URI.';
  return 'STARTUP_UNKNOWN: Startup failed. Check database configuration and service settings privately. No raw exception was logged.';
}
