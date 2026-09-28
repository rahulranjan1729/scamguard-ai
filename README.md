# ScamGuard AI — Real-Time Anti-Fraud & Cyber Threat Protection Agent

![ScamGuard AI Demo](demo.gif)

**ScamGuard AI** is an intelligent cybersecurity and anti-fraud assistant built with Google's Agent Development Kit (ADK). It provides real-time threat detection, live call coercion analysis, emergency caregiver alerting, threat intelligence lookups, and visual warning generation to protect users from phishing, financial, crypto, phone, and imposter scams.

---

## 🚀 Key Features & Real-Time Tools

The agent implements the following specialized tool functions wired directly to Google Cloud services:

* **🚨 Proactive Live Call Sentinel (`analyze_live_call_transcript`)**: Analyzes live phone call transcripts for high-risk coercion patterns (IRS imposter, tech support, gift card demands, crypto ATM redirection, or urgent arrest threats) and outputs risk scores.
* **🛡️ Caregiver Emergency Alerts (`notify_trusted_guardian`)**: Dispatches real-time emergency security alerts when high-risk live call coercion is detected and records the event into Cloud Firestore.
* **🔍 Phishing & URL Security Inspector (`analyze_url_security`)**: Evaluates domain entropy, TLD risk level, subdomains, and brand spoofing indicators to identify malicious phishing links.
* **🌐 Network & IP Threat Intelligence (`lookup_ip_threat_intelligence`)**: Performs IP address risk scoring, ISP lookup, and proxy/VPN detection.
* **🗄️ Scam Incident Catalog (`lookup_scam_incidents` & `log_scam_incident`)**: Queries and records verified scam reports in Cloud Firestore.
* **📍 Geolocation & Safety Navigation (`geocode_address` & `search_nearby_places`)**: Converts addresses to coordinates and locates nearby police stations or bank branches for physical safety assistance.
* **🎨 Threat Warning Infographics (`generate_threat_warning_infographic`)**: Generates visual threat warning graphics using Vertex AI Imagen 3 (`imagen-3.0-generate-002`) and publishes them to Google Cloud Storage.
* **🎬 Animated Threat Video Generator (`generate_threat_warning_video`)**: Generates short animated warning clips using Google's Omni model (`gemini-omni-flash-preview`) in the global region and publishes video bytes to Google Cloud Storage.
* **🧠 Conversation Memory Bank (`load_memory_tool` & `preload_memory_tool`)**: Maintains persistent user interaction context and security preferences across sessions.
* **📱 Responsive A2UI Cards (`A2uiSchemaManager v0.8`)**: Formats agent threat assessments and safety alerts into structured A2UI cards.

---

## 🛠️ Google Cloud & Architecture Integration

* **Agent Framework**: Google Agent Development Kit (`google-adk`) with `gemini-2.5-flash` model.
* **Deployment Target**: Google Vertex AI Agent Runtime / Reasoning Engine (`us-east1`).
* **Database Persistence**: Google Cloud Firestore (`scam_incidents` and `guardian_alerts` collections).
* **Asset Storage**: Google Cloud Storage (`gs://scamguard-assets-qwiklabs-gcp-03-c7f26ed5ce67`).
* **Generative Media**: Vertex AI Imagen 3 (`imagen-3.0-generate-002`) & Gemini Omni (`gemini-omni-flash-preview`).
* **Location Services**: Google Maps Platform (Geocoding & Places APIs).
* **Frontend Proxy**: FastAPI Agent-to-Agent (A2A) proxy with dark slate/cyan UI theme.

---

## 📋 Planned / Future Capabilities

The following features were outlined during initial design but are not yet implemented in the current codebase:
* *Twilio SMS & Voice API Integration* (planned, not yet implemented — alerts currently persist to Firestore).
* *Automated Browser Extension Auto-Blocker* (planned, not yet implemented).

---

## 💻 Local Setup & Execution Guide

### Prerequisites
* Python 3.11+
* `uv` package manager (`pip install uv`)
* Google Cloud CLI (`gcloud`) authenticated to your GCP project with Firestore and Cloud Storage enabled.

### 1. Install Dependencies
```bash
# Clone repository and navigate to project directory
cd scamguard-ai

# Install agent dependencies
uv sync
```

### 2. Set Environment Variables
```bash
export GOOGLE_CLOUD_PROJECT="<YOUR_GCP_PROJECT_ID>"
export GOOGLE_LOCATION="us-east1"
export GOOGLE_MAPS_API_KEY="<YOUR_GOOGLE_MAPS_API_KEY>"
export AGENT_ENGINE_RESOURCE_NAME="<YOUR_AGENT_ENGINE_RESOURCE_NAME>"
export AGENT_DIRECTORY="app"
```

### 3. Run Agent Locally with ADK Web Playground
```bash
# Start local ADK web interface
uv run adk web app --port 8000
```

### 4. Run Frontend Proxy Locally
```bash
# Install frontend dependencies and launch FastAPI server
cd frontend
uv run uvicorn main:app --host 0.0.0.0 --port 8080
```

---

## 📦 Deployment Instructions

### Deploy Agent to Vertex AI Agent Runtime
```bash
agents-cli deploy \
  --project "<YOUR_GCP_PROJECT_ID>" \
  --no-confirm-project \
  --update-env-vars GOOGLE_MAPS_API_KEY="<YOUR_GOOGLE_MAPS_API_KEY>"
```

### Deploy Frontend Proxy to Cloud Run
```bash
cd frontend
gcloud run deploy scamguard-frontend \
  --source . \
  --region us-east1 \
  --allow-unauthenticated \
  --set-env-vars AGENT_ENGINE_RESOURCE_NAME="<YOUR_AGENT_ENGINE_RESOURCE_NAME>",AGENT_DIRECTORY="app"
```
