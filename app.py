import os
import uuid
import base64
import requests
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from PIL import Image
from io import BytesIO
import random

def favorites_locked():
    """
    Retourne True si la date actuelle est postérieure ou égale au 16 avril 2025 à 21h (heure de Paris)
    """
    lock_deadline = datetime.strptime("2025-04-16 21:00", "%Y-%m-%d %H:%M")
    lock_deadline = lock_deadline.replace(tzinfo=ZoneInfo("Europe/Paris"))
    now = datetime.now(ZoneInfo("Europe/Paris"))
    return now >= lock_deadline

# Charger les variables d'environnement
load_dotenv()

AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY")
BASE_ID = os.getenv("BASE_ID")
TABLE_USERS = os.getenv("TABLE_USERS", "Users")
SECRET_KEY = os.getenv("SECRET_KEY", "DefaultKeyIfMissing")

app = Flask(__name__)
app.secret_key = SECRET_KEY

UPLOAD_FOLDER = "static/uploads"
TABLE_CANDIDATS = "Candidats"
TABLE_PREDICTIONS = "Predictions"

# Définir la date de début du concours
CONTEST_START = "2025-03-26 21:00"

def airtable_headers():
    return {
        "Authorization": f"Bearer {AIRTABLE_API_KEY}",
        "Content-Type": "application/json"
    }

def get_current_week():
    try:
        contest_start = datetime.strptime(CONTEST_START, "%Y-%m-%d %H:%M")
        contest_start = contest_start.replace(tzinfo=ZoneInfo("Europe/Paris"))
    except Exception:
        contest_start = datetime(2025, 3, 27, 21, 0, tzinfo=ZoneInfo("Europe/Paris"))
    now = datetime.now(ZoneInfo("Europe/Paris"))
    if now < contest_start:
        return 1  # Avant le lancement, on vote pour la semaine 1.
    delta = now - contest_start
    # Normalement, la semaine actuelle serait delta.days // 7 + 1, 
    # mais on ajoute 1 pour voter pour la semaine suivante.
    week_number = delta.days // 7 + 2
    return week_number



def upload_attachment(file_path):
    """
    Upload le fichier situé à file_path via l'API beta d'Airtable pour les attachments.
    Retourne la liste d'attachements telle que demandée par Airtable.
    """
    upload_url = "https://api.airtable.com/v0/meta/beta/uploadAttachment"
    headers = {
        "Authorization": f"Bearer {AIRTABLE_API_KEY}"
    }
    with open(file_path, "rb") as f:
        files = {"attachment": f}
        response = requests.post(upload_url, headers=headers, files=files)
    if response.status_code == 200:
        return response.json()["attachment"]
    else:
        print("Upload attachment error:", response.status_code, response.text)
        return None

@app.route("/")
def home():
    return render_template("index.html")

# ---------------------
# AUTHENTIFICATION (register, login, logout)
# ---------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        username = request.form["username"]
        password = request.form["password"]

        # On ne gère pas l'upload, on choisit toujours une photo aléatoire
        import random
        random_photos = ["random1.png", "random2.jpeg", "random3.jpeg", "random4.webp", "random5.png", "random6.jpeg", "random7.webp","random8.jpg", "random9.webp"]
        selected_photo = random.choice(random_photos)
        # On génère une URL absolue pour l'image aléatoire dans static/random_photos
        photo_url = url_for('static', filename='random_photos/' + selected_photo, _external=True)

        data = {
            "fields": {
                "Email": email,
                "Username": username,
                "PasswordHash": generate_password_hash(password),
                # On stocke l'URL directement dans le champ PhotoURL
                "PhotoURL": photo_url
            }
        }
        check_url = f"https://api.airtable.com/v0/{BASE_ID}/{TABLE_USERS}"
        params = {"filterByFormula": f"{{Email}}='{email}'"}
        check_resp = requests.get(check_url, headers=airtable_headers(), params=params)
        if check_resp.status_code != 200:
            return f"Erreur lors de la vérification: {check_resp.status_code}"
        if check_resp.json().get("records", []):
            return "Cet email est déjà utilisé."
        create_url = f"https://api.airtable.com/v0/{BASE_ID}/{TABLE_USERS}"
        create_resp = requests.post(create_url, headers=airtable_headers(), json=data)
        if create_resp.status_code == 200:
            return redirect(url_for("login"))
        else:
            return f"Erreur création user: {create_resp.status_code} - {create_resp.text}"
    else:
        return render_template("register.html")



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        url = f"https://api.airtable.com/v0/{BASE_ID}/{TABLE_USERS}"
        params = {"filterByFormula": f"{{Email}}='{email}'"}
        resp = requests.get(url, headers=airtable_headers(), params=params)
        if resp.status_code != 200:
            return f"Erreur lors de la requête Airtable: {resp.status_code}"
        records = resp.json().get("records", [])
        if not records:
            return "Utilisateur non trouvé."
        user_record = records[0]
        fields = user_record["fields"]
        stored_hash = fields.get("PasswordHash", "")
        if check_password_hash(stored_hash, password):
            session["user_id"] = user_record["id"]
            session["user_email"] = fields.get("Email")
            session["username"] = fields.get("Username")
            return redirect(url_for("home"))
        else:
            return "Mot de passe incorrect."
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

# ---------------------
# PREDICTIONS
# ---------------------
@app.route("/predictions", methods=["GET"])
def predictions():
    if "user_id" not in session:
        return redirect(url_for("login"))
    current_week = get_current_week()
    user_id = session["user_id"]
    print("DEBUG GET /predictions | user_id:", user_id, "| current_week:", current_week)
    url_candidats = f"https://api.airtable.com/v0/{BASE_ID}/{TABLE_CANDIDATS}"
    params_candidats = {"filterByFormula": "OR({Status}='En compétition', {Status}='Éliminé')"}
    resp_candidats = requests.get(url_candidats, headers=airtable_headers(), params=params_candidats)
    if resp_candidats.status_code != 200:
        return f"Erreur récupération candidats: {resp_candidats.status_code} - {resp_candidats.text}"
    candidats = resp_candidats.json().get("records", [])
    url_pred = f"https://api.airtable.com/v0/{BASE_ID}/{TABLE_PREDICTIONS}"
    params_pred = {"filterByFormula": f"{{Week}}={current_week}"}
    resp_pred = requests.get(url_pred, headers=airtable_headers(), params=params_pred)
    if resp_pred.status_code != 200:
        return f"Erreur récupération prédictions: {resp_pred.status_code} - {resp_pred.text}"
    all_predictions = resp_pred.json().get("records", [])
    print("DEBUG GET /predictions | all_predictions for week:", all_predictions)
    selected_candidate = None
    for rec in all_predictions:
        user_links = rec["fields"].get("User", [])
        if user_id in user_links:
            selected_candidate = rec["fields"].get("Candidate_predicted_out", [None])[0]
            print("DEBUG GET /predictions | Found existing vote, candidate:", selected_candidate)
            break
    return render_template("predictions.html", candidats=candidats, current_week=current_week, selected_candidate=selected_candidate)

@app.route("/predictions", methods=["POST"])
def submit_prediction():
    if "user_id" not in session:
        return redirect(url_for("login"))
    candidate_id = request.form.get("candidate_id")
    current_week = get_current_week()
    user_id = session["user_id"]
    print("DEBUG POST /predictions | user_id:", user_id, "| week:", current_week, "| candidate_id:", candidate_id)
    url_pred = f"https://api.airtable.com/v0/{BASE_ID}/{TABLE_PREDICTIONS}"
    params_pred = {"filterByFormula": f"{{Week}}={current_week}"}
    check_resp = requests.get(url_pred, headers=airtable_headers(), params=params_pred)
    if check_resp.status_code != 200:
        return f"Erreur check: {check_resp.status_code} - {check_resp.text}"
    all_records = check_resp.json().get("records", [])
    print("DEBUG POST /predictions | all_records for week:", all_records)
    existing_record = None
    for r in all_records:
        user_links = r["fields"].get("User", [])
        if user_id in user_links:
            existing_record = r
            print("DEBUG POST /predictions | Found existing record:", existing_record["id"])
            break
    data = {
        "fields": {
            "User": [user_id],
            "Candidate_predicted_out": [candidate_id],
            "Week": current_week
        }
    }
    if existing_record:
        record_id = existing_record["id"]
        update_url = f"{url_pred}/{record_id}"
        update_resp = requests.patch(update_url, headers=airtable_headers(), json=data)
        if update_resp.status_code != 200:
            return f"Erreur de mise à jour de la prédiction: {update_resp.status_code} - {update_resp.text}"
        print("DEBUG POST /predictions | Updated record:", record_id)
    else:
        create_resp = requests.post(url_pred, headers=airtable_headers(), json=data)
        if create_resp.status_code != 200:
            return f"Erreur création prédiction: {create_resp.status_code} - {create_resp.text}"
        print("DEBUG POST /predictions | Created new record")
    return redirect(url_for("predictions"))

# ---------------------
# CLASSEMENT
# ---------------------
@app.route("/classement")
def classement():
    url = f"https://api.airtable.com/v0/{BASE_ID}/{TABLE_PREDICTIONS}"
    resp = requests.get(url, headers=airtable_headers())
    if resp.status_code != 200:
        return f"Erreur récupération predictions: {resp.status_code} - {resp.text}"
    records = resp.json().get("records", [])
    score_map = {}
    for rec in records:
        fields = rec["fields"]
        user_list = fields.get("User", [])
        if not user_list:
            continue
        user_id = user_list[0]
        points = fields.get("Points", 0)
        score_map[user_id] = score_map.get(user_id, 0) + points
    classement_data = []
    for user_id, total_points in score_map.items():
        user_url = f"https://api.airtable.com/v0/{BASE_ID}/{TABLE_USERS}/{user_id}"
        user_resp = requests.get(user_url, headers=airtable_headers())
        if user_resp.status_code == 200:
            user_fields = user_resp.json().get("fields", {})
            username = user_fields.get("Username", "Inconnu")
            # On récupère l'URL stockée dans le champ "PhotoURL"
            photo_url = user_fields.get("PhotoURL")
            classement_data.append({
                "username": username,
                "points": total_points,
                "photo_url": photo_url
            })
    classement_data.sort(key=lambda x: x["points"], reverse=True)
    return render_template("classement.html", classement=classement_data)


# ---------------------
# FAVORIS
# ---------------------
@app.route("/favorites", methods=["GET", "POST"])
def favorites_route():
    if "user_id" not in session:
        return redirect(url_for("login"))
    user_url = f"https://api.airtable.com/v0/{BASE_ID}/{TABLE_USERS}/{session['user_id']}"
    user_resp = requests.get(user_url, headers=airtable_headers())
    if user_resp.status_code != 200:
        return f"Erreur récupération utilisateur: {user_resp.status_code} - {user_resp.text}"
    user_fields = user_resp.json().get("fields", {})
    favorites_ids = user_fields.get("Favorites", [])
    lock = favorites_locked()
    if request.method == "POST":
        if lock:
            return "La période de modification des favoris est terminée."
        selected_ids = request.form.getlist("favorite_ids")
        if len(selected_ids) > 3:
            return "Vous ne pouvez sélectionner que 3 favoris maximum."
        update_url = f"https://api.airtable.com/v0/{BASE_ID}/{TABLE_USERS}/{session['user_id']}"
        data = {
            "fields": {
                "Favorites": selected_ids
            }
        }
        update_resp = requests.patch(update_url, headers=airtable_headers(), json=data)
        if update_resp.status_code == 200:
            return redirect(url_for("favorites_route"))
        else:
            return f"Erreur de mise à jour des favoris: {update_resp.status_code} - {update_resp.text}"
    if not lock:
        url = f"https://api.airtable.com/v0/{BASE_ID}/{TABLE_CANDIDATS}"
        params = {"filterByFormula": "{Status}='En compétition'"}
        resp = requests.get(url, headers=airtable_headers(), params=params)
        if resp.status_code != 200:
            return f"Erreur récupération candidats: {resp.status_code} - {resp.text}"
        candidats = resp.json().get("records", [])
        return render_template("favorites.html", candidats=candidats, locked=False, selected_favorites=favorites_ids)
    else:
        favorites_list = []
        for candidate_id in favorites_ids:
            candidate_url = f"https://api.airtable.com/v0/{BASE_ID}/{TABLE_CANDIDATS}/{candidate_id}"
            candidate_resp = requests.get(candidate_url, headers=airtable_headers())
            if candidate_resp.status_code == 200:
                candidate_json = candidate_resp.json()
                favorites_list.append({
                    "id": candidate_json.get("id"),
                    "fields": candidate_json.get("fields", {})
                })
        return render_template("favorites.html", favorites=favorites_list, locked=True)

# ---------------------
# ADMIN PANEL
# ---------------------
@app.route("/admin/panel", methods=["GET"])
def admin_panel():
    if "user_id" not in session:
        return redirect(url_for("login"))
    url = f"https://api.airtable.com/v0/{BASE_ID}/{TABLE_CANDIDATS}"
    params = {"filterByFormula": "{Status}='En compétition'"}
    resp = requests.get(url, headers=airtable_headers(), params=params)
    if resp.status_code != 200:
        return f"Erreur récupération candidats: {resp.status_code} - {resp.text}"
    candidats = resp.json().get("records", [])
    return render_template("admin_panel.html", candidats=candidats)

@app.route("/admin/mark_eliminated/<int:week_number>/<candidate_id>", methods=["POST"])
def mark_eliminated(week_number, candidate_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    candidate_url = f"https://api.airtable.com/v0/{BASE_ID}/{TABLE_CANDIDATS}/{candidate_id}"
    data_candidate = {
        "fields": {
            "Status": "Éliminé"
        }
    }
    candidate_resp = requests.patch(candidate_url, headers=airtable_headers(), json=data_candidate)
    if candidate_resp.status_code != 200:
        return f"Erreur mise à jour candidat: {candidate_resp.status_code} - {candidate_resp.text}"
    url_predictions = f"https://api.airtable.com/v0/{BASE_ID}/{TABLE_PREDICTIONS}"
    params = {"filterByFormula": f"{{Week}}={week_number}"}
    resp = requests.get(url_predictions, headers=airtable_headers(), params=params)
    if resp.status_code != 200:
        return f"Erreur récupération predictions: {resp.status_code} - {resp.text}"
    records = resp.json().get("records", [])
    updated_records = []
    for rec in records:
        fields = rec["fields"]
        candidate_predicted = fields.get("Candidate_predicted_out", [])
        points = 1 if candidate_predicted and candidate_predicted[0] == candidate_id else 0
        updated_records.append({
            "id": rec["id"],
            "fields": {"Points": points}
        })
    if updated_records:
        patch_resp = requests.patch(url_predictions, headers=airtable_headers(), json={"records": updated_records})
        if patch_resp.status_code != 200:
            return f"Erreur update points: {patch_resp.status_code} - {patch_resp.text}"
    return redirect(url_for("admin_panel"))

# ---------------------
# ALL PRONOSTICS
# ---------------------
@app.route("/all_pronostics")
def all_pronostics():
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    current_week = get_current_week()
    print("DEBUG all_pronostics | current_week:", current_week)
    
    url_pred = f"https://api.airtable.com/v0/{BASE_ID}/{TABLE_PREDICTIONS}"
    params = {"filterByFormula": f"{{Week}}={current_week}"}
    pred_resp = requests.get(url_pred, headers=airtable_headers(), params=params)
    if pred_resp.status_code != 200:
        all_predictions = []
    else:
        all_predictions = pred_resp.json().get("records", [])
    print("DEBUG all_pronostics | all_predictions:", all_predictions)
    
    predictions_by_user = {}
    for rec in all_predictions:
        user_list = rec["fields"].get("User", [])
        if user_list:
            predictions_by_user[user_list[0]] = rec["fields"].get("Candidate_predicted_out", [None])[0]
    print("DEBUG all_pronostics | predictions_by_user:", predictions_by_user)
    
    url_users = f"https://api.airtable.com/v0/{BASE_ID}/{TABLE_USERS}"
    resp_users = requests.get(url_users, headers=airtable_headers())
    if resp_users.status_code != 200:
        return f"Erreur récupération users: {resp_users.status_code} - {resp_users.text}"
    user_records = resp_users.json().get("records", [])
    
    pronostics_data = []
    for user_rec in user_records:
        user_id = user_rec["id"]
        user_fields = user_rec["fields"]
        username = user_fields.get("Username", "Inconnu")
        # On récupère l'URL de la photo depuis "PhotoURL"
        photo_url = user_fields.get("PhotoURL")
        favorites_ids = user_fields.get("Favorites", [])
        favorites_names = []
        for fid in favorites_ids:
            cand_url = f"https://api.airtable.com/v0/{BASE_ID}/{TABLE_CANDIDATS}/{fid}"
            cand_resp = requests.get(cand_url, headers=airtable_headers())
            if cand_resp.status_code == 200:
                cand_fields = cand_resp.json().get("fields", {})
                favorites_names.append(cand_fields.get("Name", "???"))
            else:
                favorites_names.append("???")
        
        cand_out_id = predictions_by_user.get(user_id)
        if cand_out_id:
            cand_out_url = f"https://api.airtable.com/v0/{BASE_ID}/{TABLE_CANDIDATS}/{cand_out_id}"
            cand_out_resp = requests.get(cand_out_url, headers=airtable_headers())
            if cand_out_resp.status_code == 200:
                cand_out_name = cand_out_resp.json().get("fields", {}).get("Name", "???")
            else:
                cand_out_name = "???"
        else:
            cand_out_name = "Pas de prédiction"
        
        pronostics_data.append({
            "username": username,
            "photo_url": photo_url,
            "prediction": cand_out_name,
            "favorites": favorites_names
        })
    
    return render_template("all_pronostics.html", pronostics=pronostics_data, current_week=current_week)


if __name__ == "__main__":
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)

