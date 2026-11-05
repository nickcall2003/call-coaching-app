# Call Coaching client app

Client portal and coach admin for Call Coaching & Performance. FastAPI + Postgres. All files stay in one folder.

## Put it online with Railway

1. Create a new GitHub repo and upload every file in this folder.
2. In Railway, choose New Project, then Deploy from GitHub repo, and pick the new repo.
3. In the same project, add a PostgreSQL database.
4. In the app service, open Variables and add:
   - `DATABASE_URL`: use Railway's reference to the Postgres `DATABASE_URL`
   - `ADMIN_PASSWORD`: a long password only you know
   - `SECRET_KEY`: a long random string
5. Under Settings, then Networking, add the custom domain `app.callscoaching.com`, then create the CNAME record Railway shows you in GoDaddy. This uses the domain you already own, so there's nothing new to buy.

## First steps once it's live

1. Open the site, tap Coach login, and sign in with `ADMIN_PASSWORD`.
2. Go to Money, then Payment usernames and settings, and check your Venmo, Cash App, and Apple Cash details.
3. Review the training agreement in Settings before inviting real clients.
4. Tap + Client, build the folder, and text the sign-up code.
