# Windy API

Private backend for Windy desktop. Node.js 24, MongoDB Atlas, Render.

## Deploy to Render

1. Rotate any database password previously shared in chat. Create a dedicated Atlas database user with readWrite access only to database `windy`.
2. Render Dashboard → New → Blueprint → connect this repository. Use root `render.yaml`.
3. Enter `MONGODB_URI` directly into Render's secret environment field. Use the Atlas driver URI and URL-encode the password. Never commit it or send it in chat. `MONGODB_DB` defaults to `windy`.
4. Add Render service outbound IP ranges to Atlas Network Access. Avoid opening database access to all IPs.
5. Deploy. Verify `https://YOUR-SERVICE.onrender.com/health` returns `{"ok":true}`. The free service may sleep/cold start; confirm current pricing before selecting a paid plan.

The Blueprint uses `server` as root, `npm ci --omit=dev` to build, `npm start` to start. Automatic deployment is off.

## Provision accounts

Run `npm ci` in `server`. In a trusted local shell or Render shell, supply `MONGODB_URI`, `MONGODB_DB=windy`, and `WINDY_INITIAL_PASSWORD` securely via environment, then run `npm run provision`. Avoid typing secret values in shell history. Clear the temporary password variable afterward.

Creates `admin` as admin, and `dangpk3` / `lambn` as collaborators. Existing passwords/roles are not overwritten. No accounts are created until provisioning succeeds. Passwords use salted scrypt hashes. There is no signup endpoint. Change initial passwords before real shared use.

## Desktop connection

Configure the desktop frontend `VITE_API_URL` and native compile-time `WINDY_API_URL` to the same actual Render HTTPS origin, then add only that exact origin to Tauri CSP connect-src and rebuild. No MongoDB credentials belong in the desktop app.

## Security and scope

- One shared workspace per database; admin/dev/collaborator roles checked on every API request.
- Opaque bearer sessions expire after 8 hours; only token hashes are stored in MongoDB. Active user and expiry checked for every request. Persistent login limits and request body limits.
- Admin creates batches/phases; members submit Jira keys. Collaborators edit their own HOTFIX notes only; fixing state and revision links require admin/dev. Optimistic timestamps protect concurrent HOTFIX edits.
- No source code, diffs, SVN passwords or Jira cookies are accepted by these endpoints.
- Automatic Jira/merge/commit report publishing is not implemented. Snapshot/progress collections are read-only through this API.
- No database migration, cloud deployment, or real Atlas verification is implied by this repository. Test role boundaries on staging before production.

## Tests

`cd server` then `npm test`. Tests use a fake database and do not access Atlas.
