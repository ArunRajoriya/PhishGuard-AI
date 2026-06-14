# 🚀 Deploy PhishGuard AI to Render

Complete guide to deploy your application to Render (Free tier available!)

---

## 📋 Prerequisites

1. **GitHub Account** - To host your code
2. **Render Account** - Sign up at https://render.com (Free!)
3. **VirusTotal API Key** - Your existing API key

---

## 🚀 Quick Deployment (5 Minutes)

### **Step 1: Push to GitHub**

If you haven't already:

```bash
# Initialize git repository
git init

# Add all files
git add .

# Commit
git commit -m "Initial commit - PhishGuard AI"

# Create repository on GitHub, then:
git remote add origin https://github.com/yourusername/PhishGuard-AI.git
git branch -M main
git push -u origin main
```

### **Step 2: Deploy to Render**

1. **Go to Render Dashboard**
   - Visit: https://dashboard.render.com/

2. **Click "New +"** → Select "Web Service"

3. **Connect GitHub Repository**
   - Click "Connect account" if first time
   - Select your PhishGuard-AI repository

4. **Configure Service**
   - **Name:** `phishguard-ai` (or your choice)
   - **Environment:** `Docker`
   - **Region:** Choose closest to you
   - **Branch:** `main`
   - **Plan:** `Free` (or paid if needed)

5. **Add Environment Variable**
   - Click "Advanced"
   - Add environment variable:
     - **Key:** `VT_API_KEY`
     - **Value:** Your VirusTotal API key

6. **Deploy**
   - Click "Create Web Service"
   - Wait 5-10 minutes for deployment

7. **Access Your App**
   - Render will provide a URL: `https://phishguard-ai.onrender.com`
   - Open it in your browser!

---

## 📝 Detailed Configuration

### render.yaml (Already Created!)

The `render.yaml` file is already configured:

```yaml
services:
  - type: web
    name: phishguard-ai
    env: docker
    plan: free
    region: oregon
    healthCheckPath: /health
    envVars:
      - key: VT_API_KEY
        sync: false
      - key: PORT
        value: 10000
```

### Environment Variables

You'll need to set:

| Variable | Value | Required |
|----------|-------|----------|
| `VT_API_KEY` | Your VirusTotal API key | ✅ Yes |

Render automatically sets `PORT` variable.

---

## 🔧 Manual Deployment Steps

### Option 1: Using Render Dashboard (Recommended)

1. **Login to Render**
   ```
   https://dashboard.render.com/
   ```

2. **New Web Service**
   - Click "New +"
   - Select "Web Service"

3. **Connect Repository**
   - Choose "Connect a repository"
   - Select GitHub
   - Authorize Render
   - Select PhishGuard-AI repo

4. **Configure**
   - **Name:** phishguard-ai
   - **Environment:** Docker
   - **Build Command:** (leave empty, uses Dockerfile)
   - **Start Command:** (leave empty, uses Dockerfile CMD)
   - **Plan:** Free

5. **Environment Variables**
   - Add `VT_API_KEY` with your API key

6. **Deploy**
   - Click "Create Web Service"

### Option 2: Using Render CLI

```bash
# Install Render CLI
npm install -g render-cli

# Login
render login

# Deploy
render deploy
```

---

## 🌐 Accessing Your Application

After deployment:

- **Your App:** `https://your-service-name.onrender.com`
- **API Docs:** `https://your-service-name.onrender.com/docs`
- **Health Check:** `https://your-service-name.onrender.com/health`

Example:
```
https://phishguard-ai.onrender.com
```

---

## ⚙️ Render Configuration Options

### Free Tier
- ✅ 512 MB RAM
- ✅ Shared CPU
- ✅ Automatic HTTPS
- ✅ Free SSL certificate
- ✅ Automatic deploys from Git
- ⚠️ Spins down after 15 min of inactivity
- ⚠️ 750 hours/month free

### Paid Tiers (Starting at $7/month)
- ✅ Always-on (no spin down)
- ✅ More RAM and CPU
- ✅ Faster builds
- ✅ Priority support

---

## 🔄 Automatic Deployments

Render automatically deploys when you push to GitHub:

```bash
# Make changes
# Commit and push
git add .
git commit -m "Update feature"
git push origin main

# Render automatically rebuilds and deploys!
```

---

## 📊 Monitoring

### View Logs

In Render Dashboard:
1. Go to your service
2. Click "Logs" tab
3. View real-time logs

### Health Checks

Render automatically checks `/health` endpoint:
- ✅ Healthy: Service running
- ❌ Unhealthy: Service restarting

### Metrics

View in Dashboard:
- CPU usage
- Memory usage
- Request count
- Response times

---

## 🐛 Troubleshooting

### Build Fails

**Check:**
- Dockerfile syntax
- requirements.txt is correct
- All files are committed to Git

**Solution:**
```bash
# Test locally first
docker build -t phishguard-ai .
docker run -p 8000:8000 -e VT_API_KEY=your_key phishguard-ai
```

### Service Crashes

**Check logs in Render Dashboard**

Common issues:
1. Missing `VT_API_KEY` environment variable
2. Database initialization errors
3. Port configuration

**Solution:**
- Verify environment variables
- Check logs for specific errors
- Ensure health check endpoint works

### Slow Cold Starts (Free Tier)

Free tier spins down after inactivity:
- First request after spin down takes 30-60 seconds
- Subsequent requests are fast

**Solutions:**
1. Upgrade to paid tier (no spin down)
2. Use external service to ping every 14 minutes
3. Accept the cold start delay

### Database Issues

Render ephemeral storage means:
- Database resets on every deploy
- Use persistent storage for production

**Solution for Production:**
```bash
# Add PostgreSQL database
# In Render Dashboard:
# New + → PostgreSQL
# Link to your web service
```

---

## 🔐 Security Best Practices

### Environment Variables

Never commit `.env` file:
- ✅ `.env` is in `.gitignore`
- ✅ Set variables in Render Dashboard
- ✅ Use Render's secret management

### HTTPS

Render automatically provides:
- ✅ Free SSL certificate
- ✅ HTTPS by default
- ✅ HTTP→HTTPS redirect

### API Keys

- ✅ Store in Render environment variables
- ✅ Never hardcode in code
- ✅ Rotate periodically

---

## 💰 Cost Estimation

### Free Tier
- **Cost:** $0/month
- **Limitations:** 
  - Spins down after 15 min
  - 750 hours/month
  - Shared resources

### Starter Plan ($7/month)
- Always on (no spin down)
- 512 MB RAM
- Better performance

### Standard Plan ($25/month)
- 2 GB RAM
- Better CPU
- Production-ready

---

## 🚀 Production Checklist

Before going live:

- [ ] API key configured in Render
- [ ] Health check passing
- [ ] Logs show no errors
- [ ] Can access web interface
- [ ] Can scan URLs successfully
- [ ] Consider paid tier for production
- [ ] Set up monitoring/alerts
- [ ] Configure custom domain (optional)

---

## 🌟 Custom Domain (Optional)

### Add Custom Domain

1. **In Render Dashboard:**
   - Go to your service
   - Click "Settings"
   - Scroll to "Custom Domains"
   - Click "Add Custom Domain"

2. **Enter your domain:**
   - Example: `phishguard.yourdomain.com`

3. **Update DNS:**
   - Add CNAME record in your domain provider:
   ```
   phishguard CNAME your-app.onrender.com
   ```

4. **Wait for SSL:**
   - Render auto-provisions SSL certificate
   - Takes 1-2 hours

---

## 📈 Scaling

### Horizontal Scaling

Render makes it easy:
1. Go to Settings
2. Increase instance count
3. Load balanced automatically

### Vertical Scaling

Upgrade plan:
1. Settings → Plan
2. Select higher tier
3. More RAM/CPU

---

## 🔄 Rollback

If deployment fails:

1. **Go to Render Dashboard**
2. Click your service
3. Go to "Events" tab
4. Click "Rollback" on previous successful deploy

---

## 📞 Support

### Render Support
- Docs: https://render.com/docs
- Community: https://community.render.com
- Status: https://status.render.com

### Your Application
- Check logs in Dashboard
- Test locally with Docker
- Review DEPLOYMENT_READY.md

---

## 🎯 Quick Commands

```bash
# Local testing before deploy
docker build -t phishguard-ai .
docker run -p 8000:8000 -e VT_API_KEY=your_key phishguard-ai

# Deploy to Render (auto on git push)
git add .
git commit -m "Update"
git push origin main

# View logs
# Use Render Dashboard > Logs tab
```

---

## ✅ Deployment Checklist

**Before Deployment:**
- [ ] Code pushed to GitHub
- [ ] `.env` in `.gitignore`
- [ ] Dockerfile configured
- [ ] render.yaml exists
- [ ] Model file included

**During Deployment:**
- [ ] Repository connected to Render
- [ ] Environment variables set
- [ ] Free tier selected (or paid)
- [ ] Deploy button clicked

**After Deployment:**
- [ ] Service shows "Live"
- [ ] Health check passing
- [ ] Can access URL
- [ ] Can scan URLs
- [ ] No errors in logs

---

## 🎉 Success!

Once deployed, your app will be live at:
```
https://your-app-name.onrender.com
```

Share the link and start detecting phishing URLs! 🛡️

---

## 📊 Render vs Other Platforms

| Feature | Render | Heroku | AWS |
|---------|--------|--------|-----|
| **Free Tier** | ✅ Yes | ✅ Limited | ❌ Credits only |
| **Easy Setup** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐ |
| **Docker Support** | ✅ Native | ✅ Yes | ✅ Yes |
| **Auto HTTPS** | ✅ Free | ✅ Free | 💰 Paid |
| **Auto Deploy** | ✅ Yes | ✅ Yes | ⚙️ Manual |
| **Pricing** | 💰 From $7/mo | 💰 From $7/mo | 💰 Variable |

**Render is recommended for:**
- ✅ Quick deployment
- ✅ Simple scaling
- ✅ Automatic HTTPS
- ✅ Docker support
- ✅ Good free tier

---

**🚀 Ready to deploy? Follow the steps above and your app will be live in 5 minutes! 🚀**
