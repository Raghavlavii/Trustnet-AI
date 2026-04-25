# 🛡️ TrustNet AI

### AI-Powered Scam Detection & Investigation Platform

TrustNet AI is a full-stack intelligent system that detects scams, extracts actionable intelligence, and simulates investigative conversations to gather deeper insights.

---

## 🚀 Features

* 🔍 **Scam Detection (ML Model)**
  Classifies messages as *Scam* or *Safe* with probability scoring.

* 🤖 **LLM Analysis (Groq)**
  Explains *why* a message is suspicious using AI reasoning.

* 🧠 **Intelligence Extraction**
  Automatically extracts:

  * Phone numbers
  * URLs
  * Payment details
  * Scam type & risk level

* 💬 **Follow-up Intelligence Agent**
  AI asks targeted questions to gather more scam evidence.

* 📄 **Report Generation**
  Generates structured JSON reports and downloadable files.

* 🌐 **Modern UI Dashboard**
  Cyberpunk-style interface with real-time analysis.

---

## 🧱 Tech Stack

| Layer      | Technology                               |
| ---------- | ---------------------------------------- |
| Backend    | FastAPI                                  |
| AI / LLM   | Groq API                                 |
| ML Model   | Scikit-learn                             |
| Database   | SQLite (local) / PostgreSQL (production) |
| Frontend   | HTML, CSS, JavaScript                    |
| Deployment | Render                                   |

---

## 📁 Project Structure

```
trustnet/
├── backend/
│   ├── app/
│   ├── requirements.txt
├── frontend/
│   ├── index.html
│   ├── styles.css
│   ├── script.js
├── ml/
├── render.yaml
├── README.md
```

---

## ⚙️ Setup (Local Development)

### 1. Clone repo

```bash
git clone https://github.com/YOUR_USERNAME/trustnet.git
cd trustnet/backend
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run server

```bash
uvicorn app.main:app --reload
```

### 4. Open app

```
http://localhost:8000
```

---

## 🔐 Environment Variables

Create a `.env` file or configure manually:

```
GROQ_API_KEY=your_api_key
DATABASE_URL=your_database_url
```

---

## 🌍 Deployment (Render)

1. Push code to GitHub
2. Create a Web Service on Render
3. Set:

   * Root Directory → `backend`
   * Start Command →

     ```
     uvicorn app.main:app --host 0.0.0.0 --port $PORT
     ```
4. Add environment variables
5. Deploy 🚀

---

## 🧪 Example Input

```
Congratulations! You've won ₹5000. Click here to claim now: http://fake-link.com
```

### Output:

* 🚨 Scam Detected
* 📊 Trust Score
* 🔗 Extracted URL
* 📄 Generated Report
* 💬 AI Follow-up

---

## 🎯 Use Cases

* Scam awareness tools
* Cybercrime investigation
* Fraud detection systems
* Educational demos

---

## ⚠️ Disclaimer

This is a prototype system built for educational and demonstration purposes.
Not intended for production cybersecurity use without further validation.

---

## ⭐ Support

If you found this project useful:

* ⭐ Star the repo
* 🔁 Share it
* 🚀 Build on top of it

---

## 💡 Future Improvements

* Real-time scammer interaction automation
* Advanced NLP detection models
* User authentication system
* Dashboard analytics

---
