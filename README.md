# Expiry Tracker

A Flask + MongoDB web app to help you track products by category and (optionally) get expiry notifications.

## Features

- User authentication: sign up with email OTP verification, login, logout
- Password reset via email OTP
- Category dashboard (groups products by category)
- Enable/disable notifications per product
- MongoDB-backed persistence
- Deployable to Vercel (see `vercel.json`)

## Tech Stack

- Python / Flask
- MongoDB (PyMongo)
- Flask-Mail (email OTP)
- Twilio (SMS client configured)
- bcrypt (password hashing)

## Project Structure

- `app.py` — Flask application (routes, auth, MongoDB access)
- `templates/` — HTML templates
- `static/` — static assets
- `requirements.txt` — Python dependencies
- `vercel.json` — Vercel deployment configuration
- `api/` — serverless entry (if used by Vercel)

## Getting Started (Local)

### 1) Prerequisites

- Python 3.10+ recommended
- A MongoDB instance (local or Atlas)

### 2) Install dependencies

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
