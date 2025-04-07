
# 🛡️ SafeSurf — Phishing Link Detection Website

SafeSurf is a phishing link detection web application where users can paste a URL and check whether it's **safe or potentially harmful**. The model used for classification is based on a **Voting Ensemble Algorithm**, achieving an impressive **accuracy of 93.53%**.

![SafeSurf Screenshot](/homepage.png)  
*Paste a URL and check instantly if it’s safe!*

---


## 🧠 Methodology

1. **Dataset**:  
   The dataset used was sourced from Kaggle:  
   📂 [Phishing Website Dataset on Kaggle](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset/data)

2. **Feature Extraction**:
   - Lexical Features (e.g., length of URL, number of special characters)
   - Domain-based Features (e.g., presence of HTTPS, domain age)
   - URL-based Features (e.g.,  whether it includes "www", "https" and specific query parameters)


3. **Data Preprocessing**:
   - Removed null values
   - Removed low-correlation features
   - Performed standardization (feature scaling)

4. **Model Training**:
   - Tested three ensemble models
   - **Voting Classifier** performed second best but offered best real-time performance tradeoff
   - Final accuracy: **93.53%**

_Particular details of the structure of the voting classifier along with their specific hyperparameters will be readable once the research paper gets published._
---

## 🧰 Tech Stack

- **Backend & ML**: Python, Scikit-learn, Pandas, NumPy, joblib
- **Frontend**: Streamlit
- **Deployment**: Streamlit Cloud 

---

## 📄 Research Publication

A research paper based on SafeSurf was **accepted at the DOSCI 2025 Conference**, selected from over **2000+ submissions**. 

---

## 🖼️ Screenshots



---

## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/safesurf.git
cd safesurf
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run locally:

```bash
streamlit run app.py
```

## 🚀 Deployed Application

🔗 [Access SafeSurf Here](https://himanshi3k-safe-surf-app-i3yjtl.streamlit.app/)

---
