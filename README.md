# MyPrep

MyPrep is a NEET 2027 preparation progress tracker.

## Account progress system
- Unique username: 1–16 letters/numbers only.
- 4-digit PIN, stored as a bcrypt hash.
- Username uniqueness enforced by SQLite.
- Progress is stored as a compact list of completed task keys.
- Progress saves automatically when a tick is changed.
- A server-side HttpOnly session lasts 7 days.
- After expiry, username + PIN are required again.

## Run
Requires Node.js 20+.

```bash
npm install
npm start
```

The database is created automatically as `myprep.sqlite`. Do not commit that database file.

## Deployment
The frontend and `server.js` must run on a Node-capable host. A static-only GitHub Pages deployment cannot run the account API or enforce globally unique usernames.
