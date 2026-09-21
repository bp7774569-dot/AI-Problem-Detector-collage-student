# AI Problem Detector — Vercel Version

This version keeps the original project's problem detector and security scanner, but changes the Streamlit UI into a normal web frontend with a Flask API so it can be deployed on Vercel.

## Local test

```bash
pip install -r requirements.txt
python -m flask --app api.index run
```

Open the HTML with a Vercel/local server, or deploy the folder directly to Vercel.

## Vercel

1. Upload/push this folder to GitHub.
2. In Vercel, choose **Add New Project**.
3. Import the GitHub repository.
4. Keep the project root as the folder containing `vercel.json`.
5. Click **Deploy**.

The API endpoints are:
- `POST /api/analyze`
- `POST /api/scan`
- `GET /api/health`

The original project documents the same detector features and security limitations; this Vercel version preserves those core rules.
