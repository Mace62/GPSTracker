from flask import *
from app import app
from flask import render_template, flash, request

@app.route('/')
def index():
    return render_template('index.html')