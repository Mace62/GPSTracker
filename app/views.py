from flask import *
from app import app
from flask import render_template, flash, request
import stripe

@app.route('/')
def index():
    return render_template('index.html')



####    THIS IS TEST CODE FOR THE STIRPE API IMPLEMENTATION     ####

@app.route('/charge', methods=['GET', 'POST'])
def charge():
    # Retrieve payment information from the request
    amount = request.form['amount']
    token = request.form['stripeToken']

    try:
        # Create a charge using the Stripe library
        charge = stripe.Charge.create(
            amount=amount,
            currency='gbp',
            source=token,
            description='Payment for your service'
        )
        # Handle successful payment
        return 'Payment successful!'
    except stripe.error.CardError as e:
        # Handle card errors
        return str(e), 403