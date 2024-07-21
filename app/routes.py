from flask import render_template, url_for, flash, redirect, request
from app import app, db, bcrypt
from app.forms import RegistrationForm, LoginForm, ItemForm
from app.models import User, Item
from flask_login import login_user, current_user, logout_user, login_required

@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/item/new", methods=['GET', 'POST'])
@login_required
def new_item():
    form = ItemForm()
    if form.validate_on_submit():
        item = Item(name=form.name.data, description=form.description.data)
        db.session.add(item)
        db.session.commit()
        flash('Your item has been created!', 'success')
        return redirect(url_for('list_items'))
    return render_template('crud.html', title='New Item', form=form, legend='New Item')

@app.route("/items")
@login_required
def list_items():
    items = Item.query.all()
    return render_template('list_items.html', title='Items', items=items)

@app.route("/item/<int:item_id>/update", methods=['GET', 'POST'])
@login_required
def update_item(item_id):
    item = Item.query.get_or_404(item_id)
    form = ItemForm()
    if form.validate_on_submit():
        item.name = form.name.data
        item.description = form.description.data
        db.session.commit()
        flash('Your item has been updated!', 'success')
        return redirect(url_for('list_items'))
    elif request.method == 'GET':
        form.name.data = item.name
        form.description.data = item.description
    return render_template('crud.html', title='Update Item', form=form, legend='Update Item')

@app.route("/item/<int:item_id>/delete", methods=['POST'])
@login_required
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    flash('Your item has been deleted!', 'success')
    return redirect(url_for('list_items'))

import joblib

@app.route("/predict", methods=['GET', 'POST'])
@login_required
def predict():
    if request.method == 'POST':
        # Assuming you have a form to collect input data for prediction
        # Load your trained model
        model = joblib.load('model.pkl')
        # Extract features from form data
        features = [float(request.form['feature1']), float(request.form['feature2']), ...]
        prediction = model.predict([features])
        return render_template('prediction.html', prediction=prediction)
    return render_template('prediction.html')
