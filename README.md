# MAACSYS Backend

## Environment variables

Set these in Railway or your hosting environment:

- PORT
- NODE_ENV=production
- DATABASE_URL=postgresql://user:password@host:5432/database
- CORS_ORIGIN=https://maacsys-main-production.up.railway.app
- PHILSMS_ENDPOINT=https://your-sms-provider.example/send
- PHILSMS_API_KEY=your-api-key
- PHILSMS_SENDER_ID=MAACSYS

## Database setup

Run the SQL from schema.sql against your PostgreSQL database.

## Start locally

```bash
npm install
node server.js
```

## Deploy to Railway

1. Connect this repository to Railway.
2. Set the environment variables from .env.example in the Railway dashboard.
3. Railway will start the app with the existing Procfile.
4. If PostgreSQL is not configured yet, the server will automatically fall back to its in-memory teacher store so the auth flow still works during testing.
