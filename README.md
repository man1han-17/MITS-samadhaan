# MITS Samadhan web application

This version runs as a real local web application: Python serves the pages and API, SQLite stores users and complaints, and uploaded pictures/videos are saved on the server. The separate C console program is still available in the project folder.

## Start the server

1. Double-click `Start Samadhan.command`, or open Terminal and change to the `web` folder:

   ```sh
   cd /path/to/create-a-complete-menu-driven-mits/web
   ```

2. Start the application:

   ```sh
   python3 server.py
   ```

3. Open **http://127.0.0.1:8000/** in your browser.
4. On the first visit, choose **Create account → Management** to set up your management login. Use a password with at least 10 characters. Then register student/faculty accounts and sign in.

Stop the server with **Ctrl+C** in Terminal. Start it again with `python3 server.py`; the database and uploads remain saved. Management setup is available only until the first management account is created.

## Features

- Student and faculty registration; management account setup on first run.
- Passwords are stored as salted PBKDF2-SHA256 hashes. Login sessions use random, HTTP-only cookies.
- Complaint creation with category, campus/hostel location, urgency, and actual photo/video uploads (6 files maximum, 5 MB per file).
- SQLite persistence, management search/filtering by status, category, urgency, location/text, and date, and emergency-first ordering.
- Management review, acceptance/rejection with required reason, resolution estimate, assignment, progress notes, and resolution.
- Reporter correction/resubmission, fix confirmation or reopening, and per-complaint audit history.
- Reporters can only view their own complaints and attachments; management can view all complaints.

## Server files

- `samadhan.db` — accounts, complaints, attachment metadata, sessions, and audit history.
- `uploads/` — uploaded media. Files are served only through an authenticated, ownership-checked endpoint.

Keep both the database and upload folder backed up together. Do not delete them if you need to preserve project records. Uploaded images/video are capped at 5 MB per file and 6 files per complaint (32 MB total request maximum).

## Put it online with Render

This project includes a Render Blueprint at the repository root (`render.yaml`). To deploy it:

1. Push the whole project folder to a new GitHub repository. The nested `web/.gitignore` keeps the local database and uploaded files out of Git.
2. Create a Render account, choose **New → Blueprint**, and connect that repository.
3. Render reads `render.yaml`. When asked for `MITS_SETUP_KEY`, generate a one-time setup key in Terminal with `python3 -c "import secrets; print(secrets.token_urlsafe(32))"` and paste it into Render. Save it temporarily; you'll enter it once when creating the first Management account.
4. Review the plan before applying it. This Blueprint uses a Starter web service and a 1 GB persistent disk so SQLite records and uploads survive restarts/deploys. At the current listed rates, that's about **US$7.25/month** (US$7 service + US$0.25/GB disk), before any other usage or taxes. Render's free web services do not support persistent disks, so they are not suitable for this app's SQLite/uploads.
5. Apply the Blueprint and wait for the service to finish deploying. Render gives it an `onrender.com` URL with HTTPS.
6. Open that URL, select **Create account → Management**, and enter the setup key, management ID, name, and a strong password. Then register student/faculty accounts. The setup key is only needed for this first account.

The database and uploads are stored under `/var/data` on the mounted disk. Back up that disk/database regularly. Do not commit the database, uploaded files, setup key, or passwords to GitHub.

## Scope and deployment

Locally, the app binds to `127.0.0.1`. The Render Blueprint changes this to `0.0.0.0` and enables secure session cookies behind HTTPS. This is suitable for an academic project deployment; for real institutional use, move to a production-grade application server and managed database, add monitoring/backups, and review security and privacy requirements. It uses only Python's standard library; no `pip install` is required. Run it with Python 3.9 or newer.

