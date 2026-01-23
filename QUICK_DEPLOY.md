# Quick Deployment Guide - 5 Minutes

## 🚀 Deploy to Render (Free, 24/7)

### Step 1: Push to GitHub
```bash
git add .
git commit -m "Ready for deployment"
git push origin main
```

### Step 2: Deploy on Render
1. Go to https://render.com → Sign up (free)
2. Click **"New +"** → **"Web Service"**
3. Connect your GitHub repo
4. Configure:
   - **Name:** `lemonadechains`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app`
   - **Plan:** Free
5. Add Environment Variables:
   - `RENDER=true`
   - `DOMAIN=https://www.lemonadechains.com`
6. Click **"Create Web Service"**

### Step 3: Add Custom Domain
1. In Render dashboard → Settings → Custom Domains
2. Add: `www.lemonadechains.com`
3. Copy the CNAME record
4. Add to your domain registrar's DNS settings
5. Wait 5-30 minutes for DNS to propagate

### Step 4: Update Google OAuth
1. Go to Google Cloud Console
2. APIs & Services → Credentials
3. Edit your OAuth client
4. Add to **Authorized redirect URIs:**
   - `https://your-app-name.onrender.com/callback`
   - `https://www.lemonadechains.com/callback`

### Step 5: Keep It Alive (Free Tier)
Use UptimeRobot (free):
1. Sign up at https://uptimerobot.com
2. Add monitor: `https://your-app-name.onrender.com`
3. Set interval: 5 minutes

**Done!** Your app is now live 24/7! 🎉

---

## Need Help?
See `DEPLOYMENT.md` for detailed instructions.
