import os
import requests
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import uuid

load_dotenv()  # charge les variables depuis le fichier .env

AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY")
BASE_ID = os.getenv("BASE_ID")
TABLE_USERS = os.getenv("TABLE_USERS", "Users")  # Valeur par défaut si pas défini
SECRET_KEY = os.getenv("SECRET_KEY", "DefaultKeyIfMissing")

app = Flask(__name__)
app.secret_key = SECRET_KEY

def airtable_headers():
    return {
        "Authorization": f"Bearer {AIRTABLE_API_KEY}",
        "Content-Type": "application/json"
    }

UPLOAD_FOLDER = "static/uploads"
TABLE_CANDIDATS = "Candidats"
TABLE_PREDICTIONS = "Predictions"

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        username = request.form["username"]
        password = request.form["password"]
        
        photo_url = ""  # Par défaut, pas de photo

        # Gérer l'upload du fichier image (si fourni)
        photo_file = request.files.get("photo_file")  # None si aucun fichier
        if photo_file:
            original_filename = secure_filename(photo_file.filename)
            if original_filename:
                # Générer un nom unique
                ext = os.path.splitext(original_filename)[1]
                unique_name = str(uuid.uuid4()) + ext
                save_path = os.path.join(UPLOAD_FOLDER, unique_name)
                photo_file.save(save_path)
                # Générer le chemin statique
                photo_url = url_for('static', filename='uploads/' + unique_name)

        # Préparer les données pour Airtable
        data = {
            "fields": {
                "Email": email,
                "Username": username,
                "PasswordHash": generate_password_hash(password)
            }
        }
        if photo_url:
            data["fields"]["PhotoURL"] = photo_url

        # Vérifier si l'utilisateur existe déjà
        check_url = f"https://api.airtable.com/v0/{BASE_ID}/{TABLE_USERS}"
        params = {
            "filterByFormula": f"{{Email}}='{email}'"
        }
        check_resp = requests.get(check_url, headers=airtable_headers(), params=params)
        if check_resp.status_code != 200:
            return f"Erreur lors de la vérification: {check_resp.status_code}"
        if check_resp.json().get("records", []):
            return "Cet email est déjà utilisé."

        # Créer l'utilisateur dans Airtable
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

        # Chercher l'user en base
        url = f"https://api.airtable.com/v0/{BASE_ID}/{TABLE_USERS}"
        params = {"filterByFormula": f"{{Email}}='{email}'"}
        resp = requests.get(url, headers=airtable_headers(), params=params)
        if resp.status_code != 200:
            return f"Erreur lors de la requête Airtable: {resp.status_code}"

        records = resp.json().get("records", [])
        if len(records) == 0:
            return "Utilisateur non trouvé."

        user_record = records[0]
        fields = user_record["fields"]
        stored_hash = fields.get("PasswordHash", "")

        if check_password_hash(stored_hash, password):
            # Login OK
            session["user_id"] = user_record["id"]  # ID Airtable du User
            session["user_email"] = fields.get("Email")
            session["username"] = fields.get("Username")
            return redirect(url_for("home"))
        else:
            return "Mot de passe incorrect."
    else:
        return render_template("login.html")


@app.route("/predictions", methods=["GET"])
def predictions():
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Récupérer tous les candidats "En compétition"
    url = f"https://api.airtable.com/v0/{BASE_ID}/{TABLE_CANDIDATS}"
    params = {"filterByFormula": "{Status}='En compétition'"}
    resp = requests.get(url, headers=airtable_headers(), params=params)
    if resp.status_code != 200:
        return f"Erreur récupération candidats: {resp.status_code} - {resp.text}"

    candidats = resp.json().get("records", [])
    return render_template("predictions.html", candidats=candidats)


@app.route("/predictions", methods=["POST"])
def submit_prediction():
    if "user_id" not in session:
        return redirect(url_for("login"))

    candidate_id = request.form.get("candidate_id")
    week = request.form.get("week")
    user_id = session["user_id"]

    # Vérifier s'il existe déjà une prédiction pour cet user et cette semaine
    url = f"https://api.airtable.com/v0/{BASE_ID}/{TABLE_PREDICTIONS}"
    params = {
        "filterByFormula": f"AND({{Week}}={week}, ARRAYJOIN({{User}})='{user_id}')"
    }
    check_resp = requests.get(url, headers=airtable_headers(), params=params)
    if check_resp.status_code != 200:
        return f"Erreur check: {check_resp.status_code} - {check_resp.text}"

    existing_records = check_resp.json().get("records", [])
    if len(existing_records) > 0:
        return "Tu as déjà fait une prédiction pour cette semaine !"

    # Sinon, créer la prédiction
    data = {
        "fields": {
            "User": [user_id],
            "Candidate_predicted_out": [candidate_id],
            "Week": int(week)
        }
    }
    create_resp = requests.post(url, headers=airtable_headers(), json=data)
    if create_resp.status_code != 200:
        return f"Erreur création prédiction: {create_resp.status_code} - {create_resp.text}"

    return redirect(url_for("home"))


@app.route("/classement")
def classement():
    # Récupérer toutes les prédictions
    url = f"https://api.airtable.com/v0/{BASE_ID}/{TABLE_PREDICTIONS}"
    resp = requests.get(url, headers=airtable_headers())
    if resp.status_code != 200:
        return f"Erreur récupération predictions: {resp.status_code} - {resp.text}"
    
    records = resp.json().get("records", [])
    score_map = {}  # Clé: user_id, Valeur: sum_points

    for rec in records:
        fields = rec["fields"]
        user_list = fields.get("User", [])
        if not user_list:
            continue
        user_id = user_list[0]  # Lien vers la table Users
        points = fields.get("Points", 0)

        if user_id in score_map:
            score_map[user_id] += points
        else:
            score_map[user_id] = points

    # On veut récupérer "Username" et "PhotoURL" pour chaque user
    classement_data = []
    for user_id, total_points in score_map.items():
        user_url = f"https://api.airtable.com/v0/{BASE_ID}/{TABLE_USERS}/{user_id}"
        user_resp = requests.get(user_url, headers=airtable_headers())
        if user_resp.status_code == 200:
            user_json = user_resp.json()
            user_fields = user_json["fields"]
            username = user_fields.get("Username", "Inconnu")
            photo_url = user_fields.get("PhotoURL")  # le champ pour la photo
            # Construire un dictionnaire
            classement_data.append({
                "username": username,
                "points": total_points,
                "photo_url": photo_url
            })

    # Trier du plus grand au plus petit
    classement_data.sort(key=lambda x: x["points"], reverse=True)

    return render_template("classement.html", classement=classement_data)


@app.route("/admin/update_week/<int:week_number>/<candidate_id>")
def update_points_for_week(week_number, candidate_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    # On récupère toutes les prédictions de la semaine
    url = f"https://api.airtable.com/v0/{BASE_ID}/{TABLE_PREDICTIONS}"
    params = {"filterByFormula": f"AND({{Week}}={week_number})"}
    resp = requests.get(url, headers=airtable_headers(), params=params)
    if resp.status_code != 200:
        return f"Erreur: {resp.status_code} - {resp.text}"
    
    records = resp.json().get("records", [])
    updated_records = []
    
    # Déterminer les points
    for rec in records:
        fields = rec["fields"]
        candidate_predicted = fields.get("Candidate_predicted_out", [])
        if candidate_predicted and candidate_predicted[0] == candidate_id:
            points = 1
        else:
            points = 0
        updated_records.append({
            "id": rec["id"],
            "fields": {
                "Points": points
            }
        })
    
    # Patch en bloc
    patch_resp = requests.patch(url, headers=airtable_headers(), json={"records": updated_records})
    if patch_resp.status_code != 200:
        return f"Erreur update points: {patch_resp.status_code} - {patch_resp.text}"
    
    return f"Points mis à jour avec succès pour la semaine {week_number} (candidat éliminé: {candidate_id})."


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    # Assure-toi d'avoir un dossier "static/uploads" existant
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    
    app.run(debug=True)
