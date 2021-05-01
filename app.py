from flask import Flask, render_template, redirect, url_for, request

from backend import Backend

app = Flask(__name__)

backend = Backend()

@app.route('/')
def index():
    return render_template('accueil.html', listPassword=backend.get_all_from_db())