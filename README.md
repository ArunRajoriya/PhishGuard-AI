# 🛡️ PhishGuard AI

**Threat Intelligence Powered Phishing URL Detection System**

Real-time URL security analysis using VirusTotal API and Machine Learning through an interactive web dashboard.

![Python](https://img.shields.io/badge/Python-3.12-blue) ![FastAPI](https://img.shields.io/badge/FastAPI-0.109-green) ![Docker](https://img.shields.io/badge/Docker-Ready-blue) ![License](https://img.shields.io/badge/License-MIT-yellow)

---

## ✨ Features

- ✅ Real-time URL security analysis with VirusTotal API
- 🤖 Machine Learning prediction with confidence scores
- 🎯 Risk classification: Safe / Suspicious / Phishing
- 🔴 Malicious vendor detection
- 📊 Interactive Bootstrap UI with responsive design
- ⚡ FastAPI REST backend with async support
- 💾 SQLite database for scan history and statistics
- 🐳 Production-ready Docker deployment
- 📱 Mobile-friendly interface

---

## 🚀 Quick Start

### **Option 1: Run Locally (Windows)**

1. **Get VirusTotal API Key** (Free)
   - Sign up at: https://www.virustotal.com/gui/join-us
   - Copy your API key

2. **Configure API Key**
   - Open `.env` file
   - Add: `VT_API_KEY=your_api_key_here`

3. **Start Application**
   ```bash
   start.bat
   ```

4. **Access Application**
   - Web UI: http://localhost:8000
   - API Docs: http://localhost:8000/docs

### **Option 2: Run with Docker**

1. **Install Docker Desktop**
   - Download from: https://www.docker.com/products/docker-desktop

2. **Configure API Key**
   - Edit `.env` file with your API key

3. **Start with Docker**
   ```bash
   docker-compose up -d
   ```

4. **Access Application**
   - Web UI: http://localhost:8000
   - API Docs: http://localhost:8000/docs

---

## 📋 Requirements

### Local Installation
- Python 3.12 or higher
- pip (Python package manager)
- VirusTotal API key (free tier available)

### Docker Installation
- Docker Desktop
- VirusTotal API key

---

## 🎯 Usage

### Web Interface
1. Open http://localhost:8000
2. Enter a URL in the input field
3. Click "🔍 Scan URL"
4. View detailed security analysis

### API Endpoints

**Scan URL:**
```bash
curl -X POST "http://localhost:8000/scan" -d "url=https://example.com"
```

**Get Statistics:**
```bash
curl http://localhost:8000/stats
```

**Health Check:**
```bash
curl http://localhost:8000/health
```

**View History:**
```bash
curl http://localhost:8000/api/history
```

---

## 📁 Project Structure

```
PhishGuard-AI/
├── app.py                  # Main FastAPI application
├── virustotal.py          # VirusTotal API integration
├── feature_extractor.py   # URL feature extraction
├── predictor.py           # ML predictions
├── database.py            # Database operations
├── model/
│   ├── model.pkl          # Trained ML model
│   └── train_model.py     # Model training script
├── templates/
│   └── index.html         # Web interface
├── static/
│   ├── css/
│   └── js/
├── database/
│   └── phishguard.db      # SQLite database
├── Dockerfile             # Docker configuration
├── docker-compose.yml     # Docker orchestration
├── requirements.txt       # Python dependencies
├── start.bat              # Windows startup script
└── README.md              # This file
```

---

## 🔧 Configuration

### Environment Variables (.env)
```env
VT_API_KEY=your_virustotal_api_key
```

### VirusTotal API Limits (Free Tier)
- 4 requests per minute
- 500 requests per day
- 15.5K requests per month

---

## 🐳 Docker Commands

```bash
# Start application
docker-compose up -d

# View logs
docker-compose logs -f

# Stop application
docker-compose down

# Rebuild after changes
docker-compose up -d --build

# Check status
docker-compose ps
```

---

## 🔍 How It Works

1. **User Input** - URL entered in web interface
2. **Validation** - URL format validation
3. **VirusTotal Scan** - Query 70+ antivirus engines
4. **Feature Extraction** - Extract URL characteristics
5. **ML Prediction** - Machine learning analysis
6. **Risk Assessment** - Combined threat analysis
7. **Results Display** - Detailed security report
8. **Database Storage** - Save scan history

---

## 🤖 Machine Learning Features

The ML model analyzes:
- URL length
- HTTPS presence
- Hyphen count in URL
- Number of dots in URL
- Subdomain count

---

## 🔒 Security Features

- ✅ Input validation and sanitization
- ✅ API key protection via environment variables
- ✅ Error handling with proper HTTP codes
- ✅ CORS configuration for production
- ✅ Non-root Docker user
- ✅ Secure database operations
- ✅ Request timeout handling

---

## 🛠️ Troubleshooting

### Port Already in Use
```bash
# Find and kill process on port 8000
netstat -ano | findstr :8000
taskkill /PID <PID> /F
```

### Missing Dependencies
```bash
pip install -r requirements.txt
```

### Database Issues
```bash
# Delete corrupted database (will auto-recreate)
del database\phishguard.db
```

### Docker Issues
```bash
# Complete rebuild
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

---

## 📊 API Documentation

Interactive API documentation available at:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

---

## 🚀 Production Deployment

### **Deploy to Render (Recommended - Free Tier Available!)**

1. **Push to GitHub**
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git push origin main
   ```

2. **Deploy to Render**
   - Go to https://dashboard.render.com/
   - Click "New +" → "Web Service"
   - Connect your GitHub repository
   - Set environment variable: `VT_API_KEY`
   - Click "Create Web Service"
   - Wait 5 minutes - Done! 🎉

3. **Access Your App**
   - Your URL: `https://your-app.onrender.com`

**See [RENDER_DEPLOYMENT.md](RENDER_DEPLOYMENT.md) for detailed instructions**

### **Other Deployment Options**

#### Using Docker (Local/Server)
```bash
# 1. Set environment variables
# 2. Build and deploy
docker-compose up -d

# 3. Monitor
docker-compose logs -f
```

#### Using Cloud Platforms
- **Render**: Free tier with auto-deploy (Recommended!)
- **AWS EC2**: Deploy Docker container
- **Google Cloud Run**: Use included Dockerfile
- **Heroku**: Git push deployment
- **DigitalOcean**: App Platform deployment

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [VirusTotal](https://www.virustotal.com/) - Comprehensive threat intelligence API
- [FastAPI](https://fastapi.tiangolo.com/) - Modern Python web framework
- [scikit-learn](https://scikit-learn.org/) - Machine learning library
- [Bootstrap](https://getbootstrap.com/) - Responsive UI framework

---

## 📞 Support

For issues and questions:
- Check the troubleshooting section above
- Review API documentation at `/docs`
- Check if Docker is running properly
- Verify VirusTotal API key is correct

---

## ⚠️ Disclaimer

This tool is for educational and security research purposes. Always follow responsible disclosure practices when discovering security vulnerabilities.

---

## 📈 System Requirements

### Minimum
- CPU: 1 core
- RAM: 512 MB
- Disk: 100 MB
- Network: Internet connection

### Recommended
- CPU: 2 cores
- RAM: 2 GB
- Disk: 1 GB
- Network: Stable internet connection

---

**Built with ❤️ for security and reliability**

**Status:** ✅ Production Ready | **Version:** 1.0.0 | **License:** MIT
