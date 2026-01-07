import os
import re
import pandas as pd
from datetime import datetime, date, timedelta
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, flash, redirect, url_for, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import CheckConstraint, UniqueConstraint, text
from sqlalchemy.orm import joinedload

# --- Configuration ---
app = Flask(__name__)
# Use environment variable for secret key, fallback to dev key
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-simple-v2-CHANGE-IN-PRODUCTION')
# Support PostgreSQL via environment variable, fallback to SQLite for development
database_url = os.environ.get('DATABASE_URL', 'sqlite:///inventory_v2_expiry.db')
if database_url and database_url.startswith('postgres://'):
    # Convert postgres:// to postgresql:// for SQLAlchemy
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
    print("✅ Using PostgreSQL Database")
else:
    print("⚠️  WARNING: Using SQLite Database. Data WILL BE LOST on restart!")
    print("   To fix: Deploy using the 'Blueprints' tab on Render or set DATABASE_URL.")

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))
    role = db.Column(db.String(20), default='worker', nullable=False)  # worker, manager, admin
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
    # Keeping X/Y for map compatibility, though we use flexbox now
    x = db.Column(db.Integer, default=0)
    y = db.Column(db.Integer, default=0)
    max_pallets = db.Column(db.Integer, default=28, nullable=False)  # Default capacity: 28 pallets
    
    def get_used_pallets(self):
        """Calculate used pallets based on inventory in this location"""
        # Count distinct items with quantity > 0 as a simple pallet count
        inventory_count = Inventory.query.filter_by(location_id=self.id).filter(Inventory.quantity > 0).count()
        return inventory_count
    
    def get_free_pallets(self):
        """Calculate free pallets"""
        return max(0, self.max_pallets - self.get_used_pallets())

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    username = db.Column(db.String(100)) # Store username in case user is deleted
    action = db.Column(db.String(50)) # e.g., 'ADD_ITEM', 'DELETE_USER'
    details = db.Column(db.String(500)) # Description of change
    
    user = db.relationship('User', backref='audit_logs')

# Helper for Audit Logging
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
            db.session.commit()
    except Exception as e:
        print(f"Audit Log Error: {e}")

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
        return {
            'id': self.id,
            'name': self.name,
            'sku': self.sku,
            'description': self.description,
            'brand': self.brand,
            'packing': self.packing,
            'weight': self.weight,
            'uom': self.uom
        }

class Inventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)
    quantity = db.Column(db.Float, default=0.0)
    expiry = db.Column(db.String(10)) # Format: MM/YY
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
    type = db.Column(db.String(10), nullable=False) # 'IN' or 'OUT'
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'))
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'))
    quantity = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
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
    
    __table_args__ = (
        CheckConstraint('quantity > 0', name='check_quantity_positive'),
    )

# --- Schema Migration Helper ---
def init_db():
    with app.app_context():
        try:
            print("🔄 Initializing Database...")
            db.create_all() 
            
            # Check for migrations/schema updates
            inspector = db.inspect(db.engine)
            if inspector.has_table('item'): 
                columns = [c['name'] for c in inspector.get_columns('item')]
                if 'price' not in columns:
                    print("🛠️ Migrating: Adding price column to Item")
                    db.session.execute(text("ALTER TABLE item ADD COLUMN price FLOAT DEFAULT 0.0"))
                if 'min_stock' not in columns:
                    print("🛠️ Migrating: Adding min_stock column to Item")
                    db.session.execute(text("ALTER TABLE item ADD COLUMN min_stock INTEGER DEFAULT 10"))
            
            # Ensure Admin Exists
            if 'user' in inspector.get_table_names() or inspector.has_table('user'):
                if User.query.count() == 0:
                    try:
                        print("👤 Creating default admin user...")
                        admin = User(username='admin', role='admin', active=True)
                        admin.set_password('admin123')
                        db.session.add(admin)
                        db.session.commit()
                    except Exception as e:
                        print(f"⚠️ Error creating default admin: {e}")

            db.session.commit()
            print("✅ Database Initialized Successfully")
        except Exception as e:
            print(f"❌ Database Initialization Failed: {e}")
            # Don't exit, let app try to run so /health can report error

# Run init immediately to fail fast in logs or prepare for requests
init_db()

# --- Helpers ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def resolve_location(loc_input):
    loc = Location.query.filter(Location.name.ilike(loc_input)).first()
    if loc: return loc.id
    
    nums = re.findall(r'\d+', str(loc_input))
    if nums:
        input_num = nums[0]
        for l in Location.query.all():
            l_nums = re.findall(r'\d+', l.name)
            if l_nums and l_nums[0] == input_num:
                return l.id
    return None

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
    return dt + timedelta(hours=int(hours))

# --- Routes ---

@app.route('/health')
def health_check():
    try:
        # Simple DB Check
        user_count = User.query.count()
        return jsonify({
            'status': 'ok', 
            'database': 'connected', 
            'users': user_count,
            'db_url': app.config['SQLALCHEMY_DATABASE_URI'].split('://')[0] # Only show protocol for security
        })
    except Exception as e:
        import traceback
        return jsonify({
            'status': 'error', 
            'error': str(e), 
            'traceback': traceback.format_exc()
        }), 500

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
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
        
        batch_doc_number = data.get('doc_number')
        batch_date_str = data.get('date')
        batch_remarks = data.get('remarks')
        batch_container = data.get('container_number')
        
        batch_date = None
        if batch_date_str:
            try: batch_date = datetime.strptime(batch_date_str, '%Y-%m-%d').date()
            except: batch_date = date.today()
        else: batch_date = date.today()
        
        try:
            for i in items:
                item_id = i.get('item_id')
                qty = float(i.get('quantity', 0))
                pallets = int(i.get('pallets', 0)) if i.get('pallets') else None
                loc_txt = i.get('location_id')
                expiry = i.get('expiry')
                
                if qty <= 0: return jsonify({'success': False, 'message': 'Quantity must be greater than 0'}), 400
                
                print(f"DEBUG: Processing item {item_id} at {loc_txt}, expiry={expiry}")
                
                loc_id = resolve_location(loc_txt)
                print(f"DEBUG: Resolved location '{loc_txt}' to ID {loc_id}")
                
                if not loc_id: return jsonify({'success': False, 'message': f'Location "{loc_txt}" not found'}), 400
                
                location = Location.query.get(loc_id)
                if not location: return jsonify({'success': False, 'message': 'Location not found'}), 400
                
                existing_inv = Inventory.query.filter_by(item_id=item_id, location_id=loc_id, expiry=expiry).first()
                if not existing_inv:
                    used_pallets = location.get_used_pallets()
                    if used_pallets >= location.max_pallets:
                        print(f"DEBUG: Location full. Used: {used_pallets}, Max: {location.max_pallets}")
                        return jsonify({'success': False, 'message': f'Location "{loc_txt}" is full'}), 400
                
                if existing_inv:
                    existing_inv.quantity += qty
                    if batch_doc_number: existing_inv.doc_number = batch_doc_number
                    if batch_date: existing_inv.date = batch_date
                    if pallets is not None: existing_inv.pallets = (existing_inv.pallets or 0) + pallets
                    if batch_remarks: existing_inv.remarks = batch_remarks
                    if batch_container: existing_inv.container_number = batch_container
                    existing_inv.worker_name = current_user.username
                    if existing_inv.quantity < 0: return jsonify({'success': False, 'message': 'Resulting quantity would be negative'}), 400
                else:
                    inv = Inventory(
                        item_id=item_id, location_id=loc_id, quantity=qty, expiry=expiry,
                        doc_number=batch_doc_number, date=batch_date, pallets=pallets,
                        remarks=batch_remarks, container_number=batch_container, worker_name=current_user.username
                    )
                    db.session.add(inv)
                
                trans = Transaction(
                    type='IN', item_id=item_id, location_id=loc_id, quantity=qty, user_id=current_user.id,
                    expiry=expiry, doc_number=batch_doc_number, date=batch_date, pallets=pallets,
                    remarks=batch_remarks, container_number=batch_container, worker_name=current_user.username
                )
                db.session.add(trans)
                
            db.session.commit()
            return jsonify({'success': True, 'message': 'Incoming Stock Added'})
        except Exception as e:
            db.session.rollback()
            import traceback
            print(traceback.format_exc())
            return jsonify({'success': False, 'message': str(e)}), 500

    # History: Show ALL with new fields
    # Use eager loading for history (OPTIMIZED)
    history = Transaction.query.options(
        joinedload(Transaction.item),
        joinedload(Transaction.location),
        joinedload(Transaction.user)
    ).filter_by(type='IN').order_by(Transaction.timestamp.desc()).limit(100).all()
    return render_template('incoming.html', recent_history=history, date=date)

@app.route('/outgoing', methods=['GET', 'POST'])
@login_required
def outgoing():
    if request.method == 'POST':
        data = request.get_json()
        items = data.get('items', [])
        
        batch_doc_number = data.get('doc_number')
        batch_date_str = data.get('date')
        batch_remarks = data.get('remarks')
        batch_container = data.get('container_number')
        
        batch_date = None
        if batch_date_str:
            try: batch_date = datetime.strptime(batch_date_str, '%Y-%m-%d').date()
            except: batch_date = date.today()
        else: batch_date = date.today()
        
        try:
            for i in items:
                item_id = i.get('item_id')
                qty = float(i.get('quantity', 0))
                pallets = int(i.get('pallets', 0)) if i.get('pallets') else None
                loc_txt = i.get('location_id')
                
                if qty <= 0: return jsonify({'success': False, 'message': 'Quantity must be greater than 0'}), 400
                
                loc_id = resolve_location(loc_txt)
                if not loc_id: return jsonify({'success': False, 'message': f'Location "{loc_txt}" not found'}), 400
                
                batches = Inventory.query.filter_by(item_id=item_id, location_id=loc_id).filter(Inventory.quantity > 0).all()
                def parse_expiry(b):
                    if not b.expiry: return datetime.max
                    try: return datetime.strptime(b.expiry, '%m/%y')
                    except: return datetime.max
                batches.sort(key=parse_expiry)
                
                remaining_qty_to_pick = qty
                total_available = sum(b.quantity for b in batches)
                
                if total_available < qty:
                     return {'success': False, 'message': f'Insufficient stock at {loc_txt}. Available: {total_available}, Requested: {qty}'}, 400

                for batch in batches:
                    if remaining_qty_to_pick <= 0: break
                    
                    taken = min(batch.quantity, remaining_qty_to_pick)
                    batch.quantity -= taken
                    remaining_qty_to_pick -= taken
                    
                    if batch.quantity == 0: db.session.delete(batch)

                    trans = Transaction(
                        type='OUT', item_id=item_id, location_id=loc_id, quantity=taken,
                        user_id=current_user.id, expiry=batch.expiry, doc_number=batch_doc_number,
                        date=batch_date, pallets=pallets, remarks=batch_remarks,
                        container_number=batch_container, worker_name=current_user.username
                    )
                    db.session.add(trans)
            
            db.session.commit()
            return jsonify({'success': True, 'message': 'Outgoing Stock Processed'})
        except Exception as e:
            db.session.rollback()
            import traceback
            print(traceback.format_exc())
            return jsonify({'success': False, 'message': str(e)}), 500

    # Use eager loading for history (OPTIMIZED)
    history = Transaction.query.options(
        joinedload(Transaction.item),
        joinedload(Transaction.location),
        joinedload(Transaction.user)
    ).filter_by(type='OUT').order_by(Transaction.timestamp.desc()).limit(100).all()
    return render_template('outgoing.html', recent_history=history, date=date)

@app.route('/logs')
@login_required
def logs():
    # Show all transactions, newest first
    # OPTIMIZED: Eager load relationships to prevent N+1 queries
    logs = Transaction.query.options(
        joinedload(Transaction.item),
        joinedload(Transaction.location),
        joinedload(Transaction.user)
    ).order_by(Transaction.timestamp.desc()).limit(500).all()
    
    audit_logs = AuditLog.query.options(
        joinedload(AuditLog.user)
    ).order_by(AuditLog.timestamp.desc()).limit(100).all()
    
    return render_template('logs.html', logs=logs, audit_logs=audit_logs)

@app.route('/reports')
@login_required
def reports():
    # Simple query with outerjoin to show all history (User requested "old ways" / visibility)
    query = Transaction.query

    # Filters
    search_term = request.args.get('search', '').strip()
    filter_type = request.args.get('type', 'all') 
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    brand_filter = request.args.get('brand', '').strip()
    min_qty = request.args.get('min_qty', '')
    max_qty = request.args.get('max_qty', '')

    query = query.outerjoin(Item) # Outer join to include orphans

    if filter_type == 'in': query = query.filter(Transaction.type == 'IN')
    elif filter_type == 'out': query = query.filter(Transaction.type == 'OUT')

    if start_date:
        try:
            s_dt = datetime.strptime(start_date, '%Y-%m-%d')
            query = query.filter(Transaction.timestamp >= s_dt)
        except: pass
    
    if end_date:
        try:
            e_dt = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(Transaction.timestamp < e_dt)
        except: pass

    if brand_filter:
        query = query.filter(Item.brand.ilike(f'%{brand_filter}%'))

    if min_qty:
        try: query = query.filter(db.func.abs(Transaction.quantity) >= float(min_qty))
        except: pass
    
    if max_qty:
        try: query = query.filter(db.func.abs(Transaction.quantity) <= float(max_qty))
        except: pass

    if search_term:
        term = f"%{search_term}%"
        # Avoid duplicate join if location needed, use outerjoin
        query = query.outerjoin(Location, Transaction.location_id == Location.id)\
                     .filter(
                         db.or_(
                             Item.name.ilike(term),
                             Item.sku.ilike(term),
                             Location.name.ilike(term),
                             Transaction.remarks.ilike(term),
                             Transaction.doc_number.ilike(term)
                         )
                     )

    transactions = query.order_by(Transaction.timestamp.desc()).limit(500).all()

    if request.args.get('export') == 'csv':
        selected_cols = request.args.get('cols', '').split(',')
        all_cols_map = {
            'date': 'Date', 'time': 'Time', 'type': 'Type', 'doc': 'Doc Number',
            'sku': 'SKU', 'name': 'Item Name', 'brand': 'Brand', 'loc': 'Location',
            'qty': 'Quantity', 'plts': 'Pallets', 'expiry': 'Expiry',
            'user': 'User', 'remarks': 'Remarks'
        }
        if not selected_cols or selected_cols == ['']: active_cols = all_cols_map.values()
        else: active_cols = [all_cols_map[c] for c in selected_cols if c in all_cols_map]

        data = []
        for t in transactions:
            row = {
                'Date': t.timestamp.strftime('%Y-%m-%d'),
                'Time': t.timestamp.strftime('%H:%M'),
                'Type': t.type,
                'Doc Number': t.doc_number,
                'SKU': t.item.sku if t.item else '<Deleted>',
                'Item Name': t.item.name if t.item else '<Deleted>',
                'Brand': t.item.brand if t.item else '',
                'Location': t.location.name if t.location else '<Deleted>',
                'Quantity': t.quantity,
                'Pallets': t.pallets,
                'Expiry': t.expiry,
                'User': t.worker_name or (t.user.username if t.user else 'System'),
                'Remarks': t.remarks
            }
            data.append({k: v for k, v in row.items() if k in active_cols})
        
        df = pd.DataFrame(data)
        final_cols = [c for c in active_cols if c in df.columns]
        if final_cols: df = df[final_cols]
        
        from io import BytesIO
        output = BytesIO()
        df.to_csv(output, index=False)
        output.seek(0)
        
        return Response(
            output, mimetype="text/csv",
            headers={"Content-Disposition": f"attachment;filename=inventory_report_{date.today()}.csv"}
        )

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
            sql = text(f"SELECT * FROM {current_table} LIMIT 100")
            result = db.session.execute(sql)
            columns = result.keys()
            data = [dict(zip(columns, row)) for row in result]
        except Exception as e:
            flash(f'Error querying table: {str(e)}')
    return render_template('admin_db.html', tables=tables, current_table=current_table, data=data, columns=columns)

@app.route('/admin/import_inventory', methods=['GET', 'POST'])
@login_required
def admin_import_inventory():
    if not current_user.is_admin(): return redirect(url_for('dashboard'))
    if request.method == 'POST':
        if 'file' not in request.files: return redirect(request.url)
        file = request.files['file']
        if file.filename == '' or not (file.filename.endswith('.xlsx') or file.filename.endswith('.xls')):
             return redirect(request.url)
        try:
            df = pd.read_excel(file)
            item_map = {item.sku: item.id for item in Item.query.all()}
            loc_map = {loc.name: loc.id for loc in Location.query.all()}
            new_items, new_locs = [], []
            
            rows_data = []
            for _, row in df.iterrows():
                try:
                    loc_name = str(row.iloc[0]).strip()
                    sku = str(row.iloc[1]).strip()
                    desc = str(row.iloc[2]).strip()
                    expiry_raw = str(row.iloc[3]).strip()
                    qty = float(row.iloc[4] if pd.notna(row.iloc[4]) else 0)
                    pallets = int(row.iloc[5] if len(row) > 5 and pd.notna(row.iloc[5]) else 0)

                    if not sku or sku == 'nan' or qty <= 0: continue
                    
                    if sku not in item_map:
                         if sku not in [i.sku for i in new_items]:
                            new_items.append(Item(sku=sku, name=desc, description=desc))
                    if loc_name not in loc_map:
                         if loc_name not in [l.name for l in new_locs]:
                            new_locs.append(Location(name=loc_name))
                            
                    # Date parse
                    expiry = expiry_raw # Default
                    if isinstance(expiry_raw, str):
                        try: expiry = datetime.strptime(expiry_raw, '%b-%y').strftime('%m/%y')
                        except: pass
                    
                    rows_data.append({'sku': sku, 'loc_name': loc_name, 'qty': qty, 'expiry': expiry, 'pallets': pallets})
                except: pass

            if new_items: db.session.add_all(new_items)
            if new_locs: db.session.add_all(new_locs)
            if new_items or new_locs:
                db.session.commit()
                item_map = {item.sku: item.id for item in Item.query.all()}
                loc_map = {loc.name: loc.id for loc in Location.query.all()}
            
            all_inv = Inventory.query.all()
            inv_map = {(inv.item_id, inv.location_id, inv.expiry): inv for inv in all_inv}
            
            count, errors = 0, 0
            for data in rows_data:
                try:
                    i_id = item_map.get(data['sku'])
                    l_id = loc_map.get(data['loc_name'])
                    if not i_id or not l_id: continue
                    
                    key = (i_id, l_id, data['expiry'])
                    inv = inv_map.get(key)
                    
                    if inv: inv.quantity += data['qty']
                    else:
                        inv = Inventory(item_id=i_id, location_id=l_id, quantity=data['qty'], expiry=data['expiry'], pallets=data['pallets'], worker_name=current_user.username, remarks='Bulk Import')
                        db.session.add(inv)
                        inv_map[key] = inv
                    
                    # No transaction logging per item for speed? Or just do it?
                    # Original logic had it, let's keep it but simpler
                    # Actually for pure speed, bulk insert transactions later is better, but let's stick to safe
                    # db.session.add(trans)...
                    count += 1
                except: errors += 1
            
            db.session.commit()
            flash(f'Imported {count} items.')
            log_audit('IMPORT_INVENTORY', f'Imported {count} items')
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {e}')
            
    return render_template('import_inventory.html')

@app.route('/admin/items', methods=['GET', 'POST'])
@login_required
def admin_items():
    if not current_user.is_admin():
        flash('Access denied.')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        action = request.form.get('action')
        
        if 'file' in request.files:
            file = request.files['file']
            if file and (file.filename.endswith('.xlsx') or file.filename.endswith('.xls')):
                try:
                    df = pd.read_excel(file)
                    def clean(x): return str(x).strip() if pd.notna(x) else ''
                    count = 0
                    for _, row in df.iterrows():
                        sku = clean(row.get('Item Code', '') or row.get('SKU', ''))
                        if not sku or sku == 'nan': continue
                        name = clean(row.get('Description', '') or row.get('Name', 'Unknown'))
                        item = Item.query.filter_by(sku=sku).first()
                        if not item:
                            item = Item(sku=sku, name=name, description=name, brand=clean(row.get('Brand', '')),
                                packing=clean(row.get('Packing', '')), weight=row.get('Weight', 0.0) if pd.notna(row.get('Weight')) else 0.0,
                                uom=clean(row.get('UOM', '')))
                            db.session.add(item)
                            count += 1
                        else:
                            item.name = name; item.description = name; item.brand = clean(row.get('Brand', ''))
                            item.packing = clean(row.get('Packing', '')); item.weight = row.get('Weight', 0.0) if pd.notna(row.get('Weight')) else 0.0
                            item.uom = clean(row.get('UOM', ''))
                    db.session.commit()
                    flash(f'Imported/Updated {count} items.')
                    log_audit('IMPORT_ITEMS', f'Imported {count} items')
                except Exception as e:
                    db.session.rollback(); flash(f'Error: {str(e)}')
            return redirect(url_for('admin_items'))

        if action == 'add':
            sku = request.form.get('sku')
            if Item.query.filter_by(sku=sku).first(): flash('Item exists.')
            else:
                try:
                    item = Item(sku=sku, name=request.form.get('name'), description=request.form.get('description'),
                        brand=request.form.get('brand'), packing=request.form.get('packing'),
                        weight=float(request.form.get('weight') or 0), uom=request.form.get('uom'))
                    db.session.add(item); db.session.commit(); flash('Item added.')
                    log_audit('ADD_ITEM', f'Added item {sku}')
                except Exception as e: flash(f'Error: {e}')
        elif action == 'edit':
            item = Item.query.get(request.form.get('item_id'))
            if item:
                item.sku = request.form.get('sku'); item.name = request.form.get('name')
                item.description = request.form.get('description'); item.brand = request.form.get('brand')
                item.packing = request.form.get('packing'); item.weight = float(request.form.get('weight') or 0)
                item.uom = request.form.get('uom')
                db.session.commit(); flash('Item updated.')
                log_audit('EDIT_ITEM', f'Updated item {item.sku}')
        elif action == 'delete':
            item = Item.query.get(request.form.get('item_id'))
            if item:
                Inventory.query.filter_by(item_id=item.id).delete()
                db.session.delete(item); db.session.commit(); flash('Item deleted.')
                log_audit('DELETE_ITEM', f'Deleted item {item.sku}')
                
        return redirect(url_for('admin_items'))
    
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip()
    query = Item.query
    if q: query = query.filter(db.or_(Item.name.ilike(f'%{q}%'), Item.sku.ilike(f'%{q}%'), Item.brand.ilike(f'%{q}%')))
    return render_template('admin_items.html', items=query.paginate(page=page, per_page=50), q=q)


@app.route('/admin/locations', methods=['GET', 'POST'])
@login_required
def admin_locations():
    if not current_user.is_admin():
        flash('Access denied.')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        action = request.form.get('action')
        
        if 'file' in request.files:
            file = request.files['file']
            if file and (file.filename.endswith('.xlsx') or file.filename.endswith('.xls')):
                try:
                    df = pd.read_excel(file)
                    count = 0
                    for _, row in df.iterrows():
                        name = str(row.get('Loc', '')).strip()
                        if not name or name == 'nan': continue
                        if not Location.query.filter_by(name=name).first():
                            db.session.add(Location(name=name)); count += 1
                    db.session.commit(); flash(f'Imported {count} locations.')
                    log_audit('IMPORT_LOCATIONS', f'Imported {count} locations')
                except Exception as e: flash(f'Error: {e}')
            return redirect(url_for('admin_locations'))
        
        if action == 'add':
            name = request.form.get('name')
            if Location.query.filter_by(name=name).first(): flash('Exists.')
            else:
                try: db.session.add(Location(name=name, x=int(request.form.get('x') or 0), y=int(request.form.get('y') or 0)))
                except: pass
                db.session.commit(); flash('Added.')
                log_audit('ADD_LOCATION', f'Added location {name}')
        elif action == 'edit':
            loc = Location.query.get(request.form.get('loc_id'))
            if loc:
                loc.name = request.form.get('name'); loc.x = int(request.form.get('x') or 0); loc.y = int(request.form.get('y') or 0)
                db.session.commit(); flash('Updated.')
                log_audit('EDIT_LOCATION', f'Updated {loc.name}')
        elif action == 'delete':
            loc = Location.query.get(request.form.get('loc_id'))
            if loc:
                Inventory.query.filter_by(location_id=loc.id).delete()
                db.session.delete(loc); db.session.commit(); flash('Deleted.')
                log_audit('DELETE_LOCATION', f'Deleted {loc.name}')
        
        return redirect(url_for('admin_locations'))

    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip()
    query = Location.query
    if q: query = query.filter(Location.name.ilike(f'%{q}%'))
    return render_template('admin_locations.html', locations=query.paginate(page=page, per_page=50), q=q)

    
@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
def admin_users():
    if not current_user.is_admin():
        flash('Access denied.')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add':
            username = request.form.get('username')
            password = request.form.get('password')
            role = request.form.get('role', 'worker')
            if User.query.filter_by(username=username).first(): flash('Username exists.')
            else:
                try:
                    user = User(username=username, role=role); user.set_password(password)
                    db.session.add(user); db.session.commit(); flash('User created.')
                    log_audit('ADD_USER', f'Created user {username} ({role})')
                except Exception as e: flash(f'Error: {e}')
        elif action == 'edit':
            user = User.query.get(request.form.get('user_id'))
            if user:
                user.role = request.form.get('role', user.role)
                if request.form.get('password'): user.set_password(request.form.get('password'))
                db.session.commit(); flash('User updated.')
                log_audit('EDIT_USER', f'Updated {user.username}')
        elif action == 'delete':
            user = User.query.get(request.form.get('user_id'))
            if user and user.id != current_user.id:
                user.active = False; db.session.commit(); flash('Deactivated.')
                log_audit('DEACTIVATE_USER', f'Deactivated {user.username}')
            elif user and user.id == current_user.id: flash('Cannot deactivate self.')
        
        return redirect(url_for('admin_users'))
    
    users = User.query.filter(User.active == True).all()
    return render_template('admin_users.html', users=users)


@app.route('/dashboard')
@login_required
def dashboard():
    total_items = Inventory.query.filter(Inventory.quantity > 0).count()
    total_locations = Location.query.count()
    
    # OPTIMIZED: Calculate total value in DB to handle nulls and avoid N+1
    from sqlalchemy import func
    total_value_qry = db.session.query(func.sum(Inventory.quantity * Item.price)).join(Item).filter(Inventory.quantity > 0).scalar()
    total_value = total_value_qry or 0
    
    # 4. Low Stock Items
    stock_levels = db.session.query(Item.id, Item.name, Item.min_stock, func.sum(Inventory.quantity)).outerjoin(Inventory).group_by(Item.id).all()
    low_stock_items = [{'name': s[1], 'qty': s[3] or 0, 'min': s[2]} for s in stock_levels if (s[3] or 0) < (s[2] or 0)]
    
    # 5. Expiry Check - Needs Inventory Iteration but eager load Item is not needed, just expiry string
    # Eager load item just in case we display name
    inventory = Inventory.query.options(joinedload(Inventory.item)).filter(Inventory.quantity > 0).all()
    expiring_items = [i for i in inventory if check_expiry(i.expiry) in ['expired', 'expiring']]
    
    # 6. Chart Data (Original Logic)
    last_30 = datetime.now() - timedelta(days=30)
    txs = Transaction.query.filter(Transaction.timestamp >= last_30).all()
    
    chart_data = {}
    for i in range(31):
        d = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        chart_data[d] = {'in': 0, 'out': 0}
        
    for t in txs:
        d_str = t.timestamp.strftime('%Y-%m-%d')
        if d_str in chart_data:
            chart_data[d_str][t.type.lower()] += 1
            
    dates = sorted(chart_data.keys())
    
    return render_template('dashboard.html', 
        total_items=total_items, total_locations=total_locations, total_value=total_value,
        low_stock_items=low_stock_items, expiring_items=expiring_items,
        items=inventory, locations=[], chart_dates=dates,
        chart_in=[chart_data[d]['in'] for d in dates], chart_out=[chart_data[d]['out'] for d in dates]
    )


@app.route('/warehouse')
@login_required
def warehouse():
    locations_with_items = db.session.query(Location).join(Inventory).filter(Inventory.quantity > 0).distinct().order_by(Location.name).all()
    location_data = []
    for loc in locations_with_items:
        used = loc.get_used_pallets()
        location_data.append({
            'location': loc, 'used_pallets': used, 'free_pallets': loc.get_free_pallets(),
            'max_pallets': loc.max_pallets, 'usage_percent': (used/loc.max_pallets*100) if loc.max_pallets>0 else 0,
            'inventory_items': [i for i in loc.inventory if i.quantity > 0]
        })
    return render_template('warehouse.html', location_data=location_data)

# API
@app.route('/api/items/search')
@login_required
def search_items():
    q = request.args.get('q', '')
    if not q: return {'results': []}
    items = Item.query.filter(db.or_(Item.name.ilike(f'%{q}%'), Item.sku.ilike(f'%{q}%'))).limit(10).all()
    return {'results': [{'id': i.id, 'text': f"{i.name} ({i.sku})", 'brand': i.brand} for i in items]}

@app.route('/api/location/<location_id>/inventory')
@login_required
def get_location_inventory(location_id):
    try:
        loc_id = int(location_id)
        location = Location.query.get(loc_id)
        if not location: return jsonify({'error': 'Location not found'}), 404
        inventory = db.session.query(Inventory).filter_by(location_id=loc_id).filter(Inventory.quantity > 0).all()
        results = [{
            'item_sku': i.item.sku, 'item_name': i.item.name, 'quantity': i.quantity,
            'expiry': i.expiry, 'pallets': i.pallets
        } for i in inventory if i.item]
        return jsonify({'inventory': results, 'location': {'name': location.name, 'used': location.get_used_pallets(), 'free': location.get_free_pallets()}})
    except: return jsonify({'error': 'Error'}), 500



if __name__ == '__main__':
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.run(debug=True, port=int(os.environ.get('PORT', 5001)), use_reloader=True)
