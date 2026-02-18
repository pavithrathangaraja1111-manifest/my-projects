import os
import uuid
from datetime import datetime, date
from decimal import Decimal
from flask import Flask, render_template, redirect, url_for, flash, request, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SelectField, FloatField, DateField, IntegerField, SubmitField, ValidationError
from wtforms.validators import DataRequired, NumberRange, Optional
from dateutil.relativedelta import relativedelta
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from io import BytesIO

# --- Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fd_tracker.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- FIX: Initialize CSRFProtect Globally ---
csrf = CSRFProtect(app)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'officer' or 'supervisor'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class SystemConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    interest_type = db.Column(db.String(20), default='simple') # 'simple' or 'compound'
    penalty_rate = db.Column(db.Float, default=1.0) # Percentage penalty on accrued interest

class InterestRateScheme(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tenure_months = db.Column(db.Integer, unique=True, nullable=False)
    default_rate = db.Column(db.Float, nullable=False)

class FixedDeposit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fd_number = db.Column(db.String(50), unique=True, nullable=True) 
    customer_name = db.Column(db.String(150), nullable=False)
    customer_id = db.Column(db.String(50), nullable=False)
    id_type = db.Column(db.String(50), nullable=False)
    id_number = db.Column(db.String(50), nullable=False)
    
    principal = db.Column(db.Float, nullable=False)
    tenure_months = db.Column(db.Integer, nullable=False)
    interest_rate = db.Column(db.Float, nullable=False) 
    start_date = db.Column(db.Date, nullable=False)
    maturity_date = db.Column(db.Date, nullable=False)
    maturity_amount = db.Column(db.Float, nullable=False)
    
    status = db.Column(db.String(20), default='active') 
    is_locked = db.Column(db.Boolean, default=False) 
    
    closure_date = db.Column(db.Date, nullable=True)
    closure_amount = db.Column(db.Float, nullable=True)
    penalty_applied = db.Column(db.Float, nullable=True)

# --- Forms ---
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class FDForm(FlaskForm):
    customer_name = StringField('Customer Name', validators=[DataRequired()])
    customer_id = StringField('Customer ID', validators=[DataRequired()])
    id_type = SelectField('ID Type', choices=[('passport', 'Passport'), ('national_id', 'National ID'), ('license', 'Driver License')], validators=[DataRequired()])
    id_number = StringField('ID Number', validators=[DataRequired()])
    
    principal = FloatField('Deposit Amount', validators=[DataRequired(), NumberRange(min=1, message="Amount must be greater than zero")])
    tenure_months = IntegerField('Tenure (Months)', validators=[DataRequired(), NumberRange(min=1, max=120)])
    interest_rate = FloatField('Interest Rate (% Annual)', validators=[DataRequired(), NumberRange(min=0, max=20, message="Rate must be between 0 and 20%")])
    start_date = DateField('Start Date', validators=[DataRequired()], default=date.today)
    
    submit = SubmitField('Create FD')

class ClosureForm(FlaskForm):
    closure_date = DateField('Intended Closure Date', validators=[DataRequired()])
    submit = SubmitField('Confirm Closure')

class ConfigForm(FlaskForm):
    interest_type = SelectField('Interest Type', choices=[('simple', 'Simple Interest'), ('compound', 'Annual Compounding')], validators=[DataRequired()])
    penalty_rate = FloatField('Penalty Rate (% on Accrued Interest)', validators=[DataRequired(), NumberRange(min=0, max=100)])
    submit = SubmitField('Update Settings')

# --- Helper Functions ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def calculate_fd(principal, rate, tenure_months, start_date, interest_type):
    rate_decimal = Decimal(str(rate)) / 100
    principal_decimal = Decimal(str(principal))
    years = Decimal(tenure_months) / 12
    
    maturity_date = start_date + relativedelta(months=tenure_months)
    
    if interest_type == 'simple':
        amount = principal_decimal * (1 + (rate_decimal * years))
    else:
        amount = principal_decimal * ( (1 + rate_decimal) ** years )
        
    return maturity_date, round(float(amount), 2)

def simulate_closure(fd, closure_date, penalty_rate):
    config = SystemConfig.query.first()
    if not config:
        config = SystemConfig(interest_type='simple', penalty_rate=1.0)
        db.session.add(config)
        db.session.commit()

    start_date = fd.start_date
    principal = Decimal(str(fd.principal))
    rate = Decimal(str(fd.interest_rate)) / 100
    
    delta = closure_date - start_date
    days = delta.days
    years = Decimal(days) / 365 
    
    if config.interest_type == 'simple':
        accrued_interest = principal * rate * years
    else:
        accrued_interest = principal * rate * years
    
    penalty_amt = accrued_interest * (Decimal(str(penalty_rate)) / 100)
    net_interest = accrued_interest - penalty_amt
    payable = principal + net_interest
    
    return {
        'accrued_interest': round(float(accrued_interest), 2),
        'penalty_amount': round(float(penalty_amt), 2),
        'payable_amount': round(float(payable), 2),
        'principal': float(principal)
    }

def generate_pdf_receipt(fd):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []
    
    elements.append(Paragraph("Fixed Deposit Receipt", styles['Title']))
    elements.append(Spacer(1, 20))
    
    data = [
        ['FD Account Number:', fd.fd_number],
        ['Customer Name:', fd.customer_name],
        ['Customer ID:', fd.customer_id],
        ['ID Type/Number:', f"{fd.id_type} - {fd.id_number}"],
        ['Principal Amount:', f"${fd.principal:,.2f}"],
        ['Interest Rate:', f"{fd.interest_rate}%"],
        ['Tenure:', f"{fd.tenure_months} Months"],
        ['Start Date:', fd.start_date.strftime('%Y-%m-%d')],
        ['Maturity Date:', fd.maturity_date.strftime('%Y-%m-%d')],
        ['Maturity Amount:', f"${fd.maturity_amount:,.2f}"],
        ['Status:', fd.status.upper()],
    ]
    
    if fd.status == 'closed':
        data.append(['Closure Date:', fd.closure_date.strftime('%Y-%m-%d')])
        data.append(['Payout Amount:', f"${fd.closure_amount:,.2f}"])

    t = Table(data, colWidths=[200, 300])
    t.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 11),
        ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
        ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
    ]))
    
    elements.append(t)
    elements.append(Spacer(1, 50))
    
    elements.append(Paragraph("_________________________", styles['Normal']))
    elements.append(Paragraph("Authorized Signature", styles['Normal']))
    
    doc.build(elements)
    buffer.seek(0)
    return buffer

# --- Routes ---

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    status_filter = request.args.get('status', 'all')
    customer_search = request.args.get('customer', '')
    date_from = request.args.get('from', '')
    date_to = request.args.get('to', '')

    query = FixedDeposit.query
    
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    if customer_search:
        query = query.filter(FixedDeposit.customer_name.ilike(f'%{customer_search}%'))
    
    if date_from:
        query = query.filter(FixedDeposit.start_date >= datetime.strptime(date_from, '%Y-%m-%d').date())
    if date_to:
        query = query.filter(FixedDeposit.start_date <= datetime.strptime(date_to, '%Y-%m-%d').date())
        
    fds = query.order_by(FixedDeposit.start_date.desc()).all()
    return render_template('dashboard.html', fds=fds, status_filter=status_filter, customer_search=customer_search, date_from=date_from, date_to=date_to)

@app.route('/fd/create', methods=['GET', 'POST'])
@login_required
def create_fd():
    form = FDForm()
    config = SystemConfig.query.first()
    
    if form.validate_on_submit():
        if not config:
            flash('System configuration missing. Supervisor must setup system first.', 'danger')
            return redirect(url_for('create_fd'))
            
        maturity_date, maturity_amount = calculate_fd(
            form.principal.data,
            form.interest_rate.data,
            form.tenure_months.data,
            form.start_date.data,
            config.interest_type
        )
        
        fd_number = f"FD-{datetime.now().strftime('%Y%m')}-{uuid.uuid4().hex[:6].upper()}"
        
        fd = FixedDeposit(
            fd_number=fd_number,
            customer_name=form.customer_name.data,
            customer_id=form.customer_id.data,
            id_type=form.id_type.data,
            id_number=form.id_number.data,
            principal=form.principal.data,
            tenure_months=form.tenure_months.data,
            interest_rate=form.interest_rate.data,
            start_date=form.start_date.data,
            maturity_date=maturity_date,
            maturity_amount=maturity_amount,
            status='active'
        )
        
        db.session.add(fd)
        db.session.commit()
        
        flash(f'FD Created Successfully. FD Number: {fd_number}', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('create_fd.html', form=form, config=config)

@app.route('/fd/close/<int:fd_id>', methods=['GET', 'POST'])
@login_required
def premature_close_fd(fd_id):
    fd = FixedDeposit.query.get_or_404(fd_id)
    
    if fd.status == 'closed' or fd.is_locked:
        flash('This FD is already closed and locked.', 'warning')
        return redirect(url_for('dashboard'))
        
    config = SystemConfig.query.first()
    form = ClosureForm()
    
    simulation = None
    
    if request.method == 'GET':
        form.closure_date.data = date.today()
    
    # Logic for POST (Simulate or Confirm)
    if form.validate_on_submit():
        closure_date = form.closure_date.data
        
        # --- VALIDATION: Check Date Logic ---
        if closure_date <= fd.start_date:
            flash('Error: Please select correct date. Closure date must be after the start date.', 'danger')
            simulation = None # Do not show simulation
        else:
            # Valid date, proceed with calculation
            # Optional: Check if trying to close in the future (allowed for simulation, but maybe warned)
            if closure_date > date.today():
                flash('Warning: Simulating for a future date.', 'info')
            
            simulation = simulate_closure(fd, closure_date, config.penalty_rate if config else 1.0)

        # Handle Confirm Button (Only if simulation was successful)
        if simulation and request.form.get('confirm') == 'confirm':
            fd.status = 'closed'
            fd.is_locked = True
            fd.closure_date = closure_date
            fd.closure_amount = simulation['payable_amount']
            fd.penalty_applied = simulation['penalty_amount']
            
            db.session.commit()
            flash('FD Closed Successfully.', 'success')
            return redirect(url_for('dashboard'))
            
    return render_template('closure.html', fd=fd, form=form, simulation=simulation)

@app.route('/fd/receipt/<int:fd_id>')
@login_required
def download_receipt(fd_id):
    fd = FixedDeposit.query.get_or_404(fd_id)
    buffer = generate_pdf_receipt(fd)
    response = make_response(buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=FD_Receipt_{fd.fd_number}.pdf'
    return response

# --- Supervisor Routes ---
@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
def admin_settings():
    if current_user.role != 'supervisor':
        flash('Access Denied.', 'danger')
        return redirect(url_for('dashboard'))
        
    config = SystemConfig.query.first()
    if not config:
        config = SystemConfig(interest_type='simple', penalty_rate=1.0)
        db.session.add(config)
        db.session.commit()
        
    form = ConfigForm(obj=config)
    
    if form.validate_on_submit():
        config.interest_type = form.interest_type.data
        config.penalty_rate = form.penalty_rate.data
        db.session.commit()
        flash('System Settings Updated.', 'success')
        
    schemes = InterestRateScheme.query.all()
    return render_template('settings.html', form=form, schemes=schemes)

@app.route('/admin/scheme/add', methods=['POST'])
@login_required
def add_scheme():
    if current_user.role != 'supervisor':
        return redirect(url_for('dashboard'))
        
    months = request.form.get('months')
    rate = request.form.get('rate')
    
    if months and rate:
        existing = InterestRateScheme.query.filter_by(tenure_months=months).first()
        if existing:
            existing.default_rate = rate
        else:
            scheme = InterestRateScheme(tenure_months=months, default_rate=rate)
            db.session.add(scheme)
        db.session.commit()
        
    return redirect(url_for('admin_settings'))

# --- Initialization ---
def create_initial_data():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            sup = User(username='admin', role='supervisor')
            sup.set_password('admin')
            db.session.add(sup)
            
            off = User(username='officer', role='officer')
            off.set_password('officer')
            db.session.add(off)
            
            db.session.commit()
            print("Initial users created (admin/admin, officer/officer)")

if __name__ == '__main__':
    create_initial_data()
    app.run(debug=True, port=5000)