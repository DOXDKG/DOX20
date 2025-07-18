# Backend Deployment Instructions for Vercel

## Setup Instructions

1. **Install Vercel CLI (if not already installed):**
   ```bash
   npm install -g vercel
   ```

2. **Deploy to Vercel:**
   ```bash
   vercel
   ```
   - Follow the prompts to link your project
   - Choose "Python" as the framework
   - The `vercel.json` file is already configured

3. **Environment Variables:**
   - Set up the following environment variables in your Vercel dashboard:
     - `ADMIN_USERNAME` (optional, defaults to "admin")
     - `ADMIN_PASSWORD_HASH` (optional, will use default if not set)
     - `SECRET_KEY` (optional, will generate if not set)
     - `API_URL` (optional, defaults to "https://leakosintapi.com/")

4. **Files included:**
   - `src/main.py` - Main Flask application
   - `requirements.txt` - Python dependencies
   - `vercel.json` - Vercel configuration
   - `wsgi.py` - WSGI entry point

## Features

- **Backend Status Page:** Visit your Vercel URL to see a status page with logo
- **Health Check:** `/health` endpoint for monitoring
- **Phone Lookup API:** `/lookup` endpoint for phone number searches
- **Admin Panel:** Various `/admin/*` endpoints for management

## Important Notes

- The backend includes a visual status page with logo at the root URL
- CORS is enabled for all origins to work with Netlify frontend
- Database is SQLite-based and will be created automatically
- Session files and database will persist across deployments

