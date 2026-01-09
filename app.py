import os
import re
import json
import pandas as pd
import traceback
import threading
import time
import uuid
import tempfile
from datetime import datetime, date, timedelta
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, flash, redirect, url_for, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import CheckConstraint, UniqueConstraint, text, or_, desc, func
from sqlalchemy.orm import joinedload
from sqlalchemy.exc import IntegrityError

# --- Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-simple-v2-CHANGE-IN-PRODUCTION')
database_url = os.environ.get('DATABASE_URL', 'sqlite:///inventory_v2_expiry.db')

if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
    
if database_url and 'postgresql' in database_url:
    if 'sslmode' not in database_url:
        joiner = '&' if '?' in database_url else '?'
        database_url = f"{database_url}{joiner}sslmode=require"
    print("✅ Using PostgreSQL Database (SSL Enforced)")
else:
    print("⚠️  WARNING: Using SQLite Database. Data WILL BE LOST on restart!")

# Log masked URL for debugging
if database_url:
    masked = re.sub(r':([^@]+)@', ':****@', database_url)
    print(f"🔌 Connection String: {masked}")

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# CRITICAL FIX 1: Connection Pool Settings
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'pool_timeout': 30,
    'pool_size': 10,
    'max_overflow': 20,
}

# Postgres-specific args (Render)
if 'sqlite' not in database_url:
    app.config['SQLALCHEMY_ENGINE_OPTIONS']['connect_args'] = {
        'connect_timeout': 10,
        'application_name': 'inventory_app'
    }

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Legacy global removed (switched to file-based)
# import_progress = {}

# CRITICAL FIX 2: Session Management
@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

# --- Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))
    role = db.Column(db.String(20), default='worker', nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        return self.role == 'admin' or self.username == 'admin'
    
    def is_manager(self):
        return self.role in ['manager', 'admin'] or self.username == 'admin'

class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    x = db.Column(db.Integer, default=0)
    y = db.Column(db.Integer, default=0)
    max_pallets = db.Column(db.Integer, default=28, nullable=False)
    
    def get_used_pallets(self):
        return Inventory.query.filter_by(location_id=self.id).filter(Inventory.quantity > 0).count()
    
    def get_free_pallets(self):
        return max(0, self.max_pallets - self.get_used_pallets())

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow) # CRITICAL FIX 4: utcnow
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    username = db.Column(db.String(100))
    action = db.Column(db.String(50))
    details = db.Column(db.String(500))
    user = db.relationship('User', backref='audit_logs')

def log_audit(action, details):
    try:
        if current_user.is_authenticated:
            log = AuditLog(
                user_id=current_user.id,
                username=current_user.username,
                action=action,
                details=details
            )
            db.session.add(log)
            # CRITICAL FIX 6: Use flush instead of commit to assume part of larger trans if needed, 
            # but here we want immediate log. However, to be safe against nesting:
            db.session.commit()
    except Exception as e:
        print(f"Audit Log Error: {e}")
        db.session.rollback()

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    sku = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200)) 
    brand = db.Column(db.String(50))
    packing = db.Column(db.String(50))
    weight = db.Column(db.Float)
    uom = db.Column(db.String(20))
    price = db.Column(db.Float, default=0.0)
    min_stock = db.Column(db.Integer, default=10)

    def to_dict(self):
        return {'id': self.id, 'name': self.name, 'sku': self.sku, 'brand': self.brand}

class Inventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)
    quantity = db.Column(db.Float, default=0.0)
    expiry = db.Column(db.String(10)) 
    doc_number = db.Column(db.String(50)) 
    date = db.Column(db.Date, default=date.today) 
    pallets = db.Column(db.Integer) 
    remarks = db.Column(db.String(200)) 
    container_number = db.Column(db.String(50)) 
    worker_name = db.Column(db.String(100)) 
    
    item = db.relationship('Item', backref='inventory')
    location = db.relationship('Location', backref='inventory')
    
    __table_args__ = (
        UniqueConstraint('item_id', 'location_id', 'expiry', name='unique_inventory_batch'),
        CheckConstraint('quantity >= 0', name='check_quantity_non_negative'),
    )

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(10), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'))
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'))
    quantity = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow) # CRITICAL FIX 4
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    expiry = db.Column(db.String(10)) 
    doc_number = db.Column(db.String(50)) 
    date = db.Column(db.Date, default=date.today) 
    pallets = db.Column(db.Integer) 
    remarks = db.Column(db.String(200)) 
    container_number = db.Column(db.String(50)) 
    worker_name = db.Column(db.String(100)) 
    
    item = db.relationship('Item')
    location = db.relationship('Location')
    user = db.relationship('User', backref='transactions')
    
    __table_args__ = (CheckConstraint('quantity > 0', name='check_quantity_positive'),)

# --- DB Initialization Fix (Split) ---
def create_tables():
    """Fast initialization"""
    with app.app_context():
        try:
            db.create_all()
            print("✅ Database Tables Verified")
        except Exception as e:
            print(f"❌ Table Verification Failed: {e}")

def run_migrations():
    """Slow initialization: Check columns and migrate schema"""
    with app.app_context():
        try:
            print("🔄 Checking Schema & Running Migrations...")
            db.create_all() 
            inspector = db.inspect(db.engine)
            if inspector.has_table('item'): 
                columns = [c['name'] for c in inspector.get_columns('item')]
                migratable = {
                    'name': "VARCHAR(100) DEFAULT 'Unknown'",
                    'sku': "VARCHAR(50)",
                    'description': "VARCHAR(200)",
                    'brand': "VARCHAR(50)",
                    'packing': "VARCHAR(50)",
                    'weight': "FLOAT DEFAULT 0.0",
                    'uom': "VARCHAR(20)",
                    'price': "FLOAT DEFAULT 0.0",
                    'min_stock': "INTEGER DEFAULT 10"
                }
                for col, defn in migratable.items():
                    if col not in columns:
                        print(f"🛠️ Migrating: Adding {col} column")
                        db.session.execute(text(f"ALTER TABLE item ADD COLUMN {col} {defn}"))
                
                rogue_columns = ['Item Code', 'Description', 'Brand', 'Packing', 'Weight', 'UOM', 'Price', 'Min Stock']
                for rogue in rogue_columns:
                    if rogue in columns:
                         try: db.session.execute(text(f'ALTER TABLE item ALTER COLUMN "{rogue}" DROP NOT NULL'))
                         except: pass

            if inspector.has_table('location'):
                columns = [c['name'] for c in inspector.get_columns('location')]
                if 'x' not in columns: db.session.execute(text("ALTER TABLE location ADD COLUMN x INTEGER DEFAULT 0"))
                if 'y' not in columns: db.session.execute(text("ALTER TABLE location ADD COLUMN y INTEGER DEFAULT 0"))
                if 'max_pallets' not in columns: db.session.execute(text("ALTER TABLE location ADD COLUMN max_pallets INTEGER DEFAULT 28"))
            
            # Ensure Admin Exists
            if 'user' in inspector.get_table_names() or inspector.has_table('user'):
                if User.query.count() == 0:
                    try:
                        admin = User(username='admin', role='admin', active=True)
                        admin.set_password('admin123')
                        db.session.add(admin)
                        db.session.commit()
                    except Exception as e: print(f"⚠️ Error creating default admin: {e}")

            db.session.commit()
            print("✅ Database Migrated Successfully")
        except Exception as e:
            print(f"❌ Database Migration Failed: {e}")

@app.route('/init-db')
def manual_init():
    try:
        run_migrations()
        return jsonify({"status": "success", "message": "Database initialized & Tables migrated."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.before_request
def initialize_database_on_first_request():
    if not app.config.get('DB_INITIALIZED'):
        app.config['DB_INITIALIZED'] = True
        try: create_tables()
        except Exception as e: print(f"❌ Critical Init Error: {e}")

# --- Helpers ---
@login_manager.user_loader
def load_user(user_id):
    try: return User.query.get(int(user_id))
    except: return None

def resolve_location(loc_input):
    if not loc_input: return None
    loc = Location.query.filter(Location.name.ilike(loc_input)).first()
    if loc: return loc.id
    nums = re.findall(r'\d+', str(loc_input))
    if nums:
        input_num = nums[0]
        for l in Location.query.all():
            l_nums = re.findall(r'\d+', l.name)
            if l_nums and l_nums[0] == input_num: return l.id
    return None

# CRITICAL FIX 3: Global Template Filter
@app.template_filter('check_expiry')
def check_expiry(expiry_str):
    if not expiry_str: return ''
    try:
        parts = expiry_str.split('/')
        if len(parts) != 2: return ''
        month, year = int(parts[0]), int(parts[1])
        full_year = 2000 + year
        today = date.today()
        if month == 12: next_month = date(full_year + 1, 1, 1)
        else: next_month = date(full_year, month + 1, 1)
        last_day_of_expiry = next_month - timedelta(days=1)
        if today > last_day_of_expiry: return 'expired'
        diff = (last_day_of_expiry - today).days
        if diff < 60: return 'expiring'
        return 'ok'
    except: return ''

@app.template_filter('add_hours')
def add_hours_filter(dt, hours):
    if not dt: return dt
    try: return dt + timedelta(hours=int(hours))
    except: return dt

# --- Routes ---
@app.route('/health')
def health_check():
    try:
        return jsonify({'status': 'ok', 'database': 'connected', 'users': User.query.count()})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500

@app.errorhandler(500)
def internal_error(error):
    import traceback
    return f"<h1>500 Internal Server Error</h1><p>{error}</p><pre>{traceback.format_exc()}</pre>", 500

@app.route('/')
def index():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        try:
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                login_user(user)
                return redirect(url_for('dashboard'))
            flash('Invalid username or password')
        except Exception as e:
            flash(f'Database Connection Error: {e}')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/incoming', methods=['GET', 'POST'])
@login_required
def incoming():
    if request.method == 'POST':
        data = request.get_json()
        items = data.get('items', [])
        batch_doc = data.get('doc_number')
        batch_date_str = data.get('date')
        
        batch_date = date.today()
        if batch_date_str:
            try: batch_date = datetime.strptime(batch_date_str, '%Y-%m-%d').date()
            except: pass
            
        try:
            for i in items:
                item_id = i.get('item_id')
                qty = float(i.get('quantity', 0))
                loc_txt = i.get('location_id')
                
                if qty <= 0: return jsonify({'success': False, 'message': 'Invalid Qty'}), 400
                loc_id = resolve_location(loc_txt)
                if not loc_id: return jsonify({'success': False, 'message': f'Loc "{loc_txt}" not found'}), 400
                
                existing_inv = Inventory.query.filter_by(item_id=item_id, location_id=loc_id, expiry=i.get('expiry')).first()
                if not existing_inv:
                    # Check capacity
                    loc = Location.query.get(loc_id)
                    used = loc.get_used_pallets()
                    if used >= loc.max_pallets: return jsonify({'success': False, 'message': f'Loc "{loc.name}" full'}), 400
                    
                    inv = Inventory(
                        item_id=item_id, location_id=loc_id, quantity=qty, expiry=i.get('expiry'),
                        doc_number=batch_doc, date=batch_date, pallets=i.get('pallets'),
                        remarks=data.get('remarks'), container_number=data.get('container_number'), worker_name=current_user.username
                    )
                    db.session.add(inv)
                else:
                    existing_inv.quantity += qty
                    existing_inv.doc_number = batch_doc
                    existing_inv.date = batch_date
                
                db.session.add(Transaction(
                    type='IN', item_id=item_id, location_id=loc_id, quantity=qty, user_id=current_user.id,
                    expiry=i.get('expiry'), doc_number=batch_doc, date=batch_date,
                    remarks=data.get('remarks'), worker_name=current_user.username
                ))
            db.session.commit()
            return jsonify({'success': True})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': str(e)}), 500

    history = Transaction.query.filter_by(type='IN').options(joinedload(Transaction.item), joinedload(Transaction.location), joinedload(Transaction.user)).order_by(Transaction.timestamp.desc()).limit(100).all()
    return render_template('incoming.html', recent_history=history, date=date)

@app.route('/outgoing', methods=['GET', 'POST'])
@login_required
def outgoing():
    if request.method == 'POST':
        data = request.get_json()
        try:
            batch_date = date.today()
            if data.get('date'):
                try: batch_date = datetime.strptime(data.get('date'), '%Y-%m-%d').date()
                except: pass

            for i in data.get('items', []):
                qty = float(i.get('quantity', 0))
                if qty <= 0: continue
                loc_id = resolve_location(i.get('location_id'))
                if not loc_id: return jsonify({'success': False, 'message': 'Location not found'}), 400
                
                batches = Inventory.query.filter_by(item_id=i.get('item_id'), location_id=loc_id).filter(Inventory.quantity > 0).all()
                total = sum(b.quantity for b in batches)
                if total < qty: return jsonify({'success': False, 'message': f'Insufficient stock: {total}'}), 400
                
                # Sort expiry
                batches.sort(key=lambda b: datetime.strptime(b.expiry, '%m/%y') if b.expiry else datetime.max)
                
                remaining = qty
                for b in batches:
                    if remaining <= 0: break
                    take = min(b.quantity, remaining)
                    b.quantity -= take
                    remaining -= take
                    if b.quantity == 0: db.session.delete(b)
                    
                    db.session.add(Transaction(
                        type='OUT', item_id=i.get('item_id'), location_id=loc_id, quantity=take, user_id=current_user.id,
                        expiry=b.expiry, doc_number=data.get('doc_number'), date=batch_date,
                        remarks=data.get('remarks'), worker_name=current_user.username
                    ))
            db.session.commit()
            return jsonify({'success': True})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': str(e)}), 500

    history = Transaction.query.filter_by(type='OUT').options(joinedload(Transaction.item), joinedload(Transaction.location), joinedload(Transaction.user)).order_by(Transaction.timestamp.desc()).limit(100).all()
    return render_template('outgoing.html', recent_history=history, date=date)

@app.route('/logs')
@login_required
def logs():
    # Use joinedload to optimize
    logs = Transaction.query.options(joinedload(Transaction.item), joinedload(Transaction.location), joinedload(Transaction.user)).order_by(Transaction.timestamp.desc()).limit(500).all()
    audit_logs = AuditLog.query.options(joinedload(AuditLog.user)).order_by(AuditLog.timestamp.desc()).limit(100).all()
    return render_template('logs.html', logs=logs, audit_logs=audit_logs)

@app.route('/reports')
@login_required
def reports():
    query = Transaction.query.outerjoin(Item).outerjoin(Location)
    
    # 1. Search (Item Name, SKU, Loc Name, Doc Number)
    search = request.args.get('search', '').strip()
    if search:
        query = query.filter(or_(
            Item.name.ilike(f'%{search}%'), 
            Item.sku.ilike(f'%{search}%'), 
            Location.name.ilike(f'%{search}%'),
            Transaction.doc_number.ilike(f'%{search}%')
        ))
    
    # 2. Brand Filter
    brand = request.args.get('brand', '').strip()
    if brand:
        query = query.filter(Item.brand.ilike(f'%{brand}%'))
        
    # 3. Type Filter (IN/OUT)
    t_type = request.args.get('type', '').strip()
    if t_type:
        query = query.filter(Transaction.type == t_type.upper())
        
    # 4. Quantity Range
    try:
        min_qty_str = request.args.get('min_qty', '').strip()
        if min_qty_str:
            query = query.filter(Transaction.quantity >= float(min_qty_str))
        
        max_qty_str = request.args.get('max_qty', '').strip()
        if max_qty_str:
            query = query.filter(Transaction.quantity <= float(max_qty_str))
    except: pass
    
    # 5. Date Range
    start_date = request.args.get('start_date')
    if start_date:
        try: query = query.filter(Transaction.timestamp >= datetime.strptime(start_date, '%Y-%m-%d'))
        except: pass
        
    end_date = request.args.get('end_date')
    if end_date:
        try: 
            # End of the day
            e_date = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(Transaction.timestamp < e_date)
        except: pass

    # Export CSV Logic
    if request.args.get('export') == 'csv':
        # Fetch data (optimize with joinedload and higher limit)
        transactions = query.options(
            joinedload(Transaction.item), 
            joinedload(Transaction.location), 
            joinedload(Transaction.user)
        ).order_by(Transaction.timestamp.desc()).limit(10000).all()
        
        data = []
        for t in transactions:
            data.append({
                'Date': t.timestamp.strftime('%Y-%m-%d'),
                'Time': (t.timestamp + timedelta(hours=4)).strftime('%H:%M'),
                'Type': ('IN (+)' if t.type == 'IN' else 'OUT (-)'),
                'Doc #': t.doc_number or '-',
                'Item Code': t.item.sku if t.item else '<Deleted>',
                'Item Name': t.item.name if t.item else '<Deleted>',
                'Location': t.location.name if t.location else '<Deleted>',
                'Qty': t.quantity,
                'Brand': t.item.brand if t.item else '-',
                'Plts': t.pallets or '-',
                'Expiry': t.expiry or '-',
                'User': t.worker_name or (t.user.username if t.user else 'System'),
                'Remarks': t.remarks or '-'
            })
            
        df = pd.DataFrame(data)
        
        # Filter columns if requested
        cols_param = request.args.get('cols')
        if cols_param:
            # Map frontend keys to DataFrame columns
            key_map = {
                'date': 'Date', 'time': 'Time', 'type': 'Type', 'doc': 'Doc #',
                'sku': 'Item Code', 'name': 'Item Name', 'loc': 'Location',
                'qty': 'Qty', 'brand': 'Brand', 'plts': 'Plts',
                'expiry': 'Expiry', 'user': 'User', 'remarks': 'Remarks'
            }
            requested_cols = [key_map.get(k) for k in cols_param.split(',') if key_map.get(k)]
            if not df.empty and requested_cols:
                 valid_cols = [c for c in requested_cols if c in df.columns]
                 if valid_cols: df = df[valid_cols]
        
        return Response(
            df.to_csv(index=False),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment;filename=inventory_report_{date.today()}.csv"}
        )

    # Limit results
    transactions = query.options(
        joinedload(Transaction.item),
        joinedload(Transaction.location),
        joinedload(Transaction.user)
    ).order_by(Transaction.timestamp.desc()).limit(200).all()
    
    return render_template('reports.html', transactions=transactions, today=date.today(), timedelta=timedelta)

@app.route('/admin/db')
@login_required
def admin_db():
    if not current_user.is_admin(): return redirect(url_for('dashboard'))
    tables = sorted(list(db.metadata.tables.keys()))
    current_table = request.args.get('table')
    data = []
    columns = []
    if current_table and current_table in tables:
        try:
            result = db.session.execute(text(f"SELECT * FROM {current_table} LIMIT 100"))
            columns = result.keys()
            data = [dict(zip(columns, row)) for row in result]
        except Exception as e: flash(f'Error: {e}')
    return render_template('admin_db.html', tables=tables, current_table=current_table, data=data, columns=columns)

# Helper: File-based Progress (Safe for Gunicorn w/ Multiple Workers)
def get_progress_file(job_id):
    try:
        tmp = tempfile.gettempdir()
        return os.path.join(tmp, f"import_job_{job_id}.json")
    except: return None

def save_progress(job_id, data):
    try:
        path = get_progress_file(job_id)
        if path:
            with open(path, 'w') as f:
                json.dump(data, f)
    except Exception as e:
        print(f"Error saving progress: {e}")

def load_progress(job_id):
    try:
        path = get_progress_file(job_id)
        if path and os.path.exists(path):
            with open(path, 'r') as f:
                return json.load(f)
        return None
    except: return None

# CRITICAL FIX 4: Robust Imports (Background + File Persisted Status)
@app.route('/admin/import_inventory', methods=['GET', 'POST'])
@login_required
def admin_import_inventory():
    if not current_user.is_admin(): 
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        print("DEBUG: Import POST received") # Health Check
        
        if 'file' not in request.files: 
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '': 
            return redirect(request.url)
        
        reset_inventory = request.form.get('reset_inventory') == 'on'
        
        try:
            # Save file temporarily
            fd, temp_path = tempfile.mkstemp(suffix='.xlsx')
            os.close(fd)
            file.save(temp_path)
            
            # Generate unique job ID
            job_id = str(uuid.uuid4())
            
            # Init Progress (File Based)
            init_state = {
                'status': 'processing',
                'processed': 0,
                'total': 0,
                'errors': 0,
                'message': 'Initializing background worker...'
            }
            save_progress(job_id, init_state)
            
            # Start background processing
            u_id = current_user.id
            thread = threading.Thread(
                target=process_import_background,
                args=(temp_path, reset_inventory, u_id, job_id)
            )
            thread.daemon = True
            thread.start()
            
            print(f"DEBUG: Thread started for Job {job_id}")
            return redirect(url_for('import_progress_page', job_id=job_id))
            
        except Exception as e:
            print(f"CRITICAL STARTUP ERROR: {e}")
            flash(f'Error starting import: {e}')
            return redirect(request.url)
    
    return render_template('import_inventory.html')

def process_import_background(filepath, reset_inventory, user_id, job_id):
    """Background worker for large imports"""
    try:
        print(f"[{job_id}] Starting background import from {filepath}")
        
        # Helper to update status
        def update_status(msg, processed=0, total=0, errors=0, status='processing'):
            data = load_progress(job_id) or {}
            data.update({
                'message': msg,
                'processed': processed,
                'total': total or data.get('total', 0),
                'errors': errors or data.get('errors', 0),
                'status': status
            })
            save_progress(job_id, data)
        # Read file in chunks
        try: df = pd.read_excel(filepath, engine='openpyxl')
        except: df = pd.read_excel(filepath, engine='xlrd')
        
        total_rows = len(df)
        update_status(f'Processing {total_rows} rows...', total=total_rows)
        
        with app.app_context():
            # 1. RESET PHASE
            if reset_inventory:
                update_status('Clearing existing inventory...')
                try:
                    db.session.query(Inventory).delete()
                    db.session.commit()
                except Exception as e:
                    print(f"Reset failed: {e}")
                    db.session.rollback()
            
            # 2. PRE-LOAD MAPS
            update_status('Loading reference data...')
            item_map = {item.sku: item.id for item in Item.query.all()}
            loc_map = {loc.name: loc.id for loc in Location.query.all()}
            
            # 3. PROCESS IN CHUNKS
            CHUNK_SIZE = 100
            new_items = []
            new_locs = []
            inv_updates = {}  # Key: (item_id, loc_id, expiry) -> quantity
            current_errors = 0
            
            for idx, row in enumerate(df.itertuples(index=False)):
                try:
                    # Generic Row Parsing
                    if len(row) < 2: continue
                    loc_name = str(row[0]).strip()
                    sku = str(row[1]).strip()
                    if not sku or sku.lower() == 'nan': continue
                    
                    qty = 0
                    if len(row) > 4:
                        try: qty = float(row[4])
                        except: pass
                    if qty <= 0: continue
                    
                    # Expiry logic
                    expiry = ''
                    if len(row) > 3:
                        val = row[3]
                        if pd.notna(val):
                            try:
                                s_val = str(val).strip()
                                if isinstance(val, (datetime, date, pd.Timestamp)): expiry = val.strftime('%m/%y')
                                elif len(s_val) >= 8:
                                     try: expiry = pd.to_datetime(s_val).strftime('%m/%y')
                                     except: expiry = s_val[:10]
                                else: expiry = s_val[:10]
                            except: expiry = str(val)[:10]

                    desc = str(row[2]).strip() if len(row) > 2 else ''
                    
                    # Track New Metadata
                    if sku not in item_map:
                        new_items.append({'sku': sku, 'name': desc or 'Unknown'})
                        item_map[sku] = -1 # Placeholder
                    
                    if loc_name not in loc_map:
                        new_locs.append({'name': loc_name})
                        loc_map[loc_name] = -1
                    
                    # Queue Inventory Update
                    # We store by (SKU, LocName, Expiry) because we don't have IDs yet for new stuff
                    key = (sku, loc_name, expiry)
                    if key in inv_updates: inv_updates[key] += qty
                    else: inv_updates[key] = qty
                    
                    # Batch Metadata Commit
                    if (idx + 1) % CHUNK_SIZE == 0:
                        if new_items:
                            db.session.bulk_insert_mappings(Item, new_items)
                            db.session.flush()
                            new_skus = [x['sku'] for x in new_items]
                            for itm in Item.query.filter(Item.sku.in_(new_skus)).all():
                                item_map[itm.sku] = itm.id
                            new_items = []
                            
                        if new_locs:
                            db.session.bulk_insert_mappings(Location, new_locs)
                            db.session.flush()
                            new_lnames = [x['name'] for x in new_locs]
                            for lc in Location.query.filter(Location.name.in_(new_lnames)).all():
                                loc_map[lc.name] = lc.id
                            new_locs = []
                            
                        db.session.commit()
                        
                        update_status(f'Processed {idx + 1}/{total_rows} rows...', processed=idx+1, errors=current_errors)
                        
                except Exception as e:
                    current_errors += 1
                    print(f"Row {idx} error: {e}")

            # Final Metadata Commit
            if new_items:
                db.session.bulk_insert_mappings(Item, new_items)
                db.session.flush()
                new_skus = [x['sku'] for x in new_items]
                for itm in Item.query.filter(Item.sku.in_(new_skus)).all(): item_map[itm.sku] = itm.id
                
            if new_locs:
                db.session.bulk_insert_mappings(Location, new_locs)
                db.session.flush()
                new_lnames = [x['name'] for x in new_locs]
                for lc in Location.query.filter(Location.name.in_(new_lnames)).all(): loc_map[lc.name] = lc.id
            db.session.commit()
            
            # 4. INVENTORY UPDATES (Bulk)
            update_status('Finalizing inventory updates...', processed=total_rows, errors=current_errors)
            
            inventory_lookup = {}
            if not reset_inventory:
                 inventory_lookup = {(inv.item_id, inv.location_id, inv.expiry): inv for inv in Inventory.query.all()}
            
            worker_name = "System"
            try: worker_name = User.query.get(user_id).username
            except: pass
            
            txn_date = date.today()
            txn_ts = datetime.utcnow()
            
            txns_to_insert = []
            
            # Process aggregated updates
            for key, qty in inv_updates.items():
                sku, loc_name, expiry = key
                i_id = item_map.get(sku)
                l_id = loc_map.get(loc_name)
                
                if not i_id or not l_id: continue
                
                db_key = (i_id, l_id, expiry)
                
                if db_key in inventory_lookup:
                     inv = inventory_lookup[db_key]
                     inv.quantity += qty
                else:
                     inv = Inventory(item_id=i_id, location_id=l_id, quantity=qty, expiry=expiry, worker_name=worker_name)
                     db.session.add(inv)
                     inventory_lookup[db_key] = inv
                
                txns_to_insert.append({
                    'type': 'IN', 'item_id': i_id, 'location_id': l_id, 'quantity': qty,
                    'user_id': user_id, 'expiry': expiry, 'worker_name': worker_name,
                    'remarks': "Bulk Import/Reset" if reset_inventory else "Bulk Import",
                    'timestamp': txn_ts, 'date': txn_date
                })
            
            db.session.commit() 
            
            if txns_to_insert:
                db.session.bulk_insert_mappings(Transaction, txns_to_insert)
                db.session.commit()
            
            update_status(f'Import complete! {total_rows} rows processed.', processed=total_rows, errors=current_errors, status='completed')
            
    except Exception as e:
        data = load_progress(job_id) or {}
        data.update({'status': 'failed', 'message': f'Error: {str(e)}'})
        save_progress(job_id, data)
        print(traceback.format_exc())
    finally:
        try: os.unlink(filepath)
        except: pass

@app.route('/import_progress/<job_id>')
@login_required
def import_progress_page(job_id):
    if not current_user.is_admin(): return redirect(url_for('dashboard'))
    return render_template('import_progress.html', job_id=job_id)

@app.route('/api/import_progress/<job_id>')
@login_required
def import_progress_api(job_id):
    data = load_progress(job_id)
    if data: return jsonify(data)
    return jsonify({'status': 'not_found'}), 404

@app.route('/admin/items', methods=['GET', 'POST'])
@login_required
def admin_items():
    if not current_user.is_admin(): return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        # IMPORT LOGIC
        if 'file' in request.files:
            file = request.files['file']
            try:
                try: df = pd.read_excel(file, engine='openpyxl')
                except: df = pd.read_excel(file, engine='xlrd')
                
                clean = lambda x: str(x).strip() if pd.notna(x) else ''
                count_new, count_upd = 0, 0
                
                # Pre-load existing items to memory to avoid N+1 queries
                existing_skus = {i.sku: i for i in Item.query.all()}
                
                for idx, row in df.iterrows():
                    try:
                        sku = None
                        # Flexible Column Search
                        for col in ['SKU', 'Item Code', 'sku']:
                            if col in df.columns: sku = clean(row[col]); break
                        if not sku and len(row) > 0: sku = clean(row.iloc[0])
                        
                        if not sku or sku == 'nan': continue
                        
                        name = 'Unknown'
                        for col in ['Name', 'Description', 'name']:
                             if col in df.columns: name = clean(row[col]); break
                        
                        item = existing_skus.get(sku)
                        if item:
                            item.name = name
                            count_upd += 1
                        else:
                            item = Item(sku=sku, name=name)
                            db.session.add(item)
                            existing_skus[sku] = item # Update local map
                            count_new += 1
                        
                        # Batch Commit
                        if (idx + 1) % 50 == 0: 
                            db.session.commit()
                            
                    except Exception as e:
                        print(f"Row Error {idx}: {e}")
                        db.session.rollback()
                        continue
                
                db.session.commit()
                flash(f'Imported {count_new} new, {count_upd} updated.')
                
            except Exception as e:
                import traceback
                print(traceback.format_exc())
                flash(f'File Error: {e}')
            return redirect(url_for('admin_items'))

        # MANUAL CRUD
        try:
            if action == 'add':
                sku = request.form.get('sku')
                if Item.query.filter_by(sku=sku).first(): flash('Item exists')
                else:
                    db.session.add(Item(sku=sku, name=request.form.get('name'), description=request.form.get('description'), 
                        brand=request.form.get('brand'), min_stock=int(request.form.get('min_stock', 10))))
                    db.session.commit(); flash('Added')
            elif action == 'edit':
                item = Item.query.get(request.form.get('item_id'))
                if item:
                    item.sku = request.form.get('sku')
                    item.name = request.form.get('name')
                    item.description = request.form.get('description')
                    item.brand = request.form.get('brand')
                    item.min_stock = int(request.form.get('min_stock', 10))
                    db.session.commit(); flash('Updated')
            elif action == 'delete':
                item = Item.query.get(request.form.get('item_id'))
                if item:
                    Inventory.query.filter_by(item_id=item.id).delete()
                    db.session.delete(item); db.session.commit(); flash('Deleted')
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {e}')
            
        return redirect(url_for('admin_items'))
    
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip()
    query = Item.query
    if q: query = query.filter(or_(Item.name.ilike(f'%{q}%'), Item.sku.ilike(f'%{q}%')))
    return render_template('admin_items.html', items=query.paginate(page=page, per_page=50), q=q)

@app.route('/admin/fix-reports')
@login_required
def admin_fix_reports():
    try:
        if not current_user.is_admin(): return redirect(url_for('dashboard'))
        
        count = 0
        inventory = Inventory.query.filter(Inventory.quantity > 0).all()
        for inv in inventory:
            # Calculate total logged quantity (IN - OUT)
            txns = Transaction.query.filter_by(item_id=inv.item_id, location_id=inv.location_id).all()
            logged_qty = sum([t.quantity if t.type == 'IN' else -t.quantity for t in txns])
            
            # If Inventory is significantly higher than Logged, backfill the difference
            diff = inv.quantity - logged_qty
            if diff > 0.001:
                db.session.add(Transaction(
                    type='IN',
                    item_id=inv.item_id,
                    location_id=inv.location_id,
                    quantity=diff,
                    user_id=current_user.id,
                    timestamp=datetime.utcnow(),
                    expiry=inv.expiry,
                    worker_name='System',
                    remarks="System Correction (Backfill)"
                ))
                count += 1
        db.session.commit()
        return f"Fixed! Created {count} adjustment records. Reports should now match Inventory. <a href='/reports'>Go to Reports</a>"
    except Exception:
        db.session.rollback()
        return f"<pre>{traceback.format_exc()}</pre>"

@app.route('/admin/locations', methods=['GET', 'POST'])
@login_required
def admin_locations():
    if not current_user.is_admin(): return redirect(url_for('dashboard'))
    if request.method == 'POST':
        action = request.form.get('action')
        
        # IMPORT LOGIC
        if 'file' in request.files:
            file = request.files['file']
            try:
                try: df = pd.read_excel(file, engine='openpyxl')
                except: df = pd.read_excel(file, engine='xlrd')
                
                # Pre-load names to avoid duplicates
                existing_names = {l.name for l in Location.query.all()}
                new_in_file = set()
                count = 0
                
                for idx, row in df.iterrows():
                    try:
                        name = str(row.iloc[0]).strip() if len(row) > 0 else ''
                        if not name or name == 'nan': continue
                        if name in existing_names or name in new_in_file: continue
                        
                        db.session.add(Location(name=name))
                        new_in_file.add(name)
                        count += 1
                        
                        if count % 50 == 0: db.session.commit()
                        
                    except: pass
                
                db.session.commit()
                flash(f'Imported {count} locations.')
            except Exception as e:
                flash(f'Error: {e}')
            return redirect(url_for('admin_locations'))

        # MANUAL CRUD
        try:
            if action == 'add':
                name = request.form.get('name')
                if not Location.query.filter_by(name=name).first():
                    db.session.add(Location(name=name, x=int(request.form.get('x',0)), y=int(request.form.get('y',0)), max_pallets=int(request.form.get('max_pallets', 28))))
                    db.session.commit(); flash('Added')
            elif action == 'edit':
                loc = Location.query.get(request.form.get('loc_id'))
                if loc:
                    loc.name = request.form.get('name')
                    loc.x = int(request.form.get('x',0)); loc.y = int(request.form.get('y',0))
                    loc.max_pallets = int(request.form.get('max_pallets', 28))
                    db.session.commit(); flash('Updated')
            elif action == 'delete':
                loc = Location.query.get(request.form.get('loc_id'))
                if loc:
                    Inventory.query.filter_by(location_id=loc.id).delete()
                    db.session.delete(loc); db.session.commit(); flash('Deleted')
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {e}')
            
        return redirect(url_for('admin_locations'))

    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip()
    query = Location.query
    if q: query = query.filter(Location.name.ilike(f'%{q}%'))
    return render_template('admin_locations.html', locations=query.paginate(page=page, per_page=50), q=q)

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
def admin_users():
    if not current_user.is_admin(): return redirect(url_for('dashboard'))
    if request.method == 'POST':
        action = request.form.get('action')
        try:
            if action == 'add':
                if not User.query.filter_by(username=request.form.get('username')).first():
                    u = User(username=request.form.get('username'), role=request.form.get('role', 'worker'))
                    u.set_password(request.form.get('password'))
                    db.session.add(u); db.session.commit(); flash('User created')
            elif action == 'edit':
                u = User.query.get(request.form.get('user_id'))
                if u:
                    u.role = request.form.get('role', u.role)
                    if request.form.get('password'): u.set_password(request.form.get('password'))
                    db.session.commit(); flash('Updated')
            elif action == 'delete':
                u = User.query.get(request.form.get('user_id'))
                if u and u.id != current_user.id:
                    u.active = False; db.session.commit(); flash('Deactivated')
        except Exception as e:
            db.session.rollback(); flash(f'Error: {e}')
        return redirect(url_for('admin_users'))
    
    return render_template('admin_users.html', users=User.query.filter(User.active==True).all())

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        from sqlalchemy import func
        total_items = Inventory.query.filter(Inventory.quantity > 0).count()
        total_locations = Location.query.count()
        total_value = db.session.query(func.sum(Inventory.quantity * Item.price)).join(Item).filter(Inventory.quantity > 0).scalar() or 0
        
        # Low Stock
        low_stock = []
        low_q = db.session.query(Item.name, Item.min_stock, func.sum(Inventory.quantity)).outerjoin(Inventory).group_by(Item.id).all()
        for name, min_s, qty in low_q:
            if (qty or 0) < (min_s or 0): low_stock.append({'name': name, 'qty': qty or 0, 'min': min_s})
            
        # Expiry - Fetch only needed
        expiring = []
        # Optimization: Fetch only items with quantity > 0, and eager load Item details
        inv_items = Inventory.query.filter(Inventory.quantity > 0).options(joinedload(Inventory.item)).all()
        for i in inv_items:
            status = check_expiry(i.expiry)
            if status in ['expired', 'expiring']: expiring.append(i)
            
        # Chart Data
        last_30 = datetime.utcnow() - timedelta(days=30)
        chart_data = { (datetime.utcnow().date() - timedelta(days=i)).strftime('%Y-%m-%d'): {'in':0, 'out':0} for i in range(31) }
        
        txs = Transaction.query.filter(Transaction.timestamp >= last_30).with_entities(Transaction.type, Transaction.timestamp).all()
        for t_type, t_time in txs:
            d = t_time.strftime('%Y-%m-%d')
            if d in chart_data: chart_data[d][t_type.lower()] += 1
            
        dates = sorted(chart_data.keys())
        
        return render_template('dashboard.html', 
            total_items=total_items, total_locations=total_locations, total_value=total_value,
            low_stock_items=low_stock, expiring_items=expiring,
            chart_dates=dates, chart_in=[chart_data[d]['in'] for d in dates], chart_out=[chart_data[d]['out'] for d in dates]
        )
    except Exception as e:
        print(f"Dash Error: {e}")
        return render_template('dashboard.html', error=str(e))

@app.route('/warehouse')
@login_required
def warehouse():
    # OPTIMIZATION: Use joinedload to fetch Location + Inventory + Item in ONE query.
    # accessing l.get_used_pallets() in a loop caused N+1 queries (1 query per location).
    # This approach fetches everything once and processes in memory (super fast for <10k items).
    locs = Location.query.options(
        joinedload(Location.inventory).joinedload(Inventory.item)
    ).order_by(Location.name).all()
    
    data = []
    for l in locs:
        # Filter in-memory
        valid_inv = [i for i in l.inventory if i.quantity > 0]
        
        # Original logic hid empty locations. Preserve that? 
        # Yes, typically maps show where stuff is.
        if not valid_inv: continue 
        
        used = len(valid_inv)
        data.append({
            'location': l, 'used_pallets': used, 'free_pallets': max(0, l.max_pallets - used),
            'max_pallets': l.max_pallets, 'usage_percent': (used/l.max_pallets*100) if l.max_pallets else 0,
            'inventory_items': valid_inv
        })
    return render_template('warehouse.html', location_data=data)

@app.route('/api/items/search')
@login_required
def search_items():
    q = request.args.get('q', '')
    if not q: return {'results': []}
    items = Item.query.filter(or_(Item.name.ilike(f'%{q}%'), Item.sku.ilike(f'%{q}%'))).limit(10).all()
    return {'results': [{'id': i.id, 'text': f"{i.name} ({i.sku})", 'brand': i.brand} for i in items]}

@app.route('/api/location/<location_id>/inventory')
@login_required
def get_location_inventory(location_id):
    try:
        l = Location.query.get(int(location_id))
        if not l: return jsonify({'error': 'Not found'}), 404
        inv = [i for i in l.inventory if i.quantity > 0]
        return jsonify({
            'inventory': [{'item_sku': i.item.sku, 'item_name': i.item.name, 'quantity': i.quantity, 'expiry': i.expiry, 'pallets': i.pallets} for i in inv],
            'location': {'name': l.name, 'used': l.get_used_pallets(), 'free': l.get_free_pallets()}
        })
    except: return jsonify({'error': 'Error'}), 500

@app.route('/api/item/<item_id>/locations')
@login_required
def get_item_locations(item_id):
    try:
        # Find inventory for this item with positive quantity
        inventory = Inventory.query.filter_by(item_id=item_id).filter(Inventory.quantity > 0).join(Location).all()
        
        # Group by location (incase multiple batches in same location)
        loc_map = {}
        for inv in inventory:
            if inv.location_id not in loc_map:
                loc_map[inv.location_id] = {
                    'id': inv.location_id,
                    'name': inv.location.name,
                    'quantity': 0
                }
            loc_map[inv.location_id]['quantity'] += inv.quantity
            
        return jsonify({'locations': list(loc_map.values())})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=int(os.environ.get('PORT', 5001)), use_reloader=True)
