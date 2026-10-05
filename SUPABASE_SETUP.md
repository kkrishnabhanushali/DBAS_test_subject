# 🔌 Database Configuration & Supabase Connection Guide

## 1. What Database Is Currently Running?
Right now, the application is using the **Built-in Local Persistent Database** (`data.db.json`).
- **Status**: 🟢 **Active & 100% Operational**
- **Features**: Stores users, securely hashed passwords (bcrypt), tasks, activity logs, and account lockout data directly in your project.
- **Immediate usage**: You can register accounts, sign in, manage tasks, and test everything right now with **zero external setup**.

---

## 2. Connecting to Supabase (When You Are Ready)

The code already includes a native, full-featured **Supabase Adapter** (`src/db/supabase.js`).
To switch your database from the local store to Supabase:

### Step 1: Create a Supabase Project
1. Go to [https://supabase.com](https://supabase.com) and log in / sign up (free).
2. Click **"New Project"**.
3. Choose an organization, project name (e.g. `secure-task-manager`), and database password.
4. Select a region close to you and click **"Create new project"**.

### Step 2: Run the Database Schema
1. In your Supabase project dashboard, navigate to the **SQL Editor** on the left menu (icon: `>_`).
2. Click **"New query"**.
3. Open the file [`supabase_schema.sql`](file:///Users/kkrishnabhanushali/Documents/testsubject/supabase_schema.sql) in this repository.
4. Copy its entire contents, paste it into the Supabase SQL Editor, and click **"Run"** (or `Cmd+Enter` / `Ctrl+Enter`).
5. You will see `Success: No rows returned`. This automatically creates:
   - `users` table (with case-insensitive indexes)
   - `tasks` table (with foreign keys and status checks)
   - `login_attempts` table (for rate limiting and security lockout)
   - Row Level Security (RLS) policies

### Step 3: Get Your API Credentials
1. In Supabase, click **Project Settings** (gear icon in the left sidebar) -> **API**.
2. Find the following values:
   - **Project URL** (e.g., `https://xyzcompany.supabase.co`)
   - **Project API Keys**:
     - `anon` `public` key
     - `service_role` `secret` key (recommended for backend server access)

### Step 4: Configure the `.env` File
Open the [`.env`](file:///Users/kkrishnabhanushali/Documents/testsubject/.env) file in your project root and fill in the values:

```env
# Supabase Configuration
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_ANON_KEY=your-supabase-anon-key
SUPABASE_SERVICE_ROLE_KEY=your-supabase-service-role-key
```

### Step 5: Start or Restart the Server
In your terminal, run:
```bash
# Using the isolated virtual environment:
source .venv/bin/activate
npm start
```
You will see:
```text
[DB] Active Engine: Supabase Cloud Database (https://your-project-id.supabase.co)
[Server] Running on http://localhost:3000
```

The application will now automatically read and write all users, tasks, and security logs to your Supabase PostgreSQL cloud database!

---

## 3. Switching Back to Local Database Anytime
To switch back to the local database, simply clear or comment out the `SUPABASE_URL` in `.env`:
```env
SUPABASE_URL=
```
The server will automatically detect this and switch back to `data.db.json`.
