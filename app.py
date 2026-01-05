
import os
import re
import pandas as pd
from datetime import datetime, date, timedelta
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, flash, redirect, url_for, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import CheckConstraint, UniqueConstraint

# --- Configuration ---
app = Flask(__name__)
# Use environment variable for secret key, fallback to dev key
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-simple-v2-CHANGE-IN-PRODUCTION')
# Support PostgreSQL via environment variable, fallback to SQLite for development
database_url = os.environ.get('DATABASE_URL', 'sqlite:///inventory_v2_expiry.db')
if database_url.startswith('postgresql://'):
    # Convert postgres:// to postgresql:// for SQLAlchemy
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- Schema Migration Helper ---
def check_db_schema():
    """Manually add columns if they don't exist (for existing DBs)"""
    with app.app_context():
        try:
            # Check Item table columns
            # This is a naive check for SQLite. For Prod, use Alembic.
            inspector = db.inspect(db.engine)
            columns = [c['name'] for c in inspector.get_columns('item')]
            
            if 'price' not in columns:
                print("Migrating: Adding 'price' to Item")
                db.session.execute(db.text("ALTER TABLE item ADD COLUMN price FLOAT DEFAULT 0.0"))
                
            if 'min_stock' not in columns:
                print("Migrating: Adding 'min_stock' to Item")
                db.session.execute(db.text("ALTER TABLE item ADD COLUMN min_stock INTEGER DEFAULT 10"))
                
            # Create AuditLog table if missing
            if not inspector.has_table('audit_log'):
                print("Migrating: Creating AuditLog table")
                db.create_all() # This creates all missing tables, including AuditLog
                
            db.session.commit()
        except Exception as e:
            print(f"Schema Check Error: {e}")

check_db_schema()

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
        # In a real system, you might have a more complex calculation
        # For now, we'll use a simple approach: count inventory entries
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
    description = db.Column(db.String(200)) # Can hold Brand/Packing if needed or extend model
    # Optional fields from user excel: brand, packing, weight, uom
    # For now, simplistic approach
    brand = db.Column(db.String(50))
    packing = db.Column(db.String(50))
    weight = db.Column(db.Float)
    uom = db.Column(db.String(20))
    price = db.Column(db.Float, default=0.0)
    min_stock = db.Column(db.Integer, default=10) # Low stock alert threshold

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
    # New columns for detailed tracking
    doc_number = db.Column(db.String(50)) # HK reference document number
    date = db.Column(db.Date, default=date.today) # Transaction date
    pallets = db.Column(db.Integer) # Number of pallets
    remarks = db.Column(db.String(200)) # Additional notes/remarks
    container_number = db.Column(db.String(50)) # Container number if applicable
    worker_name = db.Column(db.String(100)) # Worker/user name who processed this
    
    item = db.relationship('Item', backref='inventory')
    location = db.relationship('Location', backref='inventory')
    
    # Add unique constraint and check constraint
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
    expiry = db.Column(db.String(10)) # Format: MM/YY
    # New columns for detailed tracking
    doc_number = db.Column(db.String(50)) # HK reference document number
    date = db.Column(db.Date, default=date.today) # Transaction date
    pallets = db.Column(db.Integer) # Number of pallets
    remarks = db.Column(db.String(200)) # Additional notes/remarks
    container_number = db.Column(db.String(50)) # Container number if applicable
    worker_name = db.Column(db.String(100)) # Worker/user name who processed this
    
    item = db.relationship('Item')
    location = db.relationship('Location')
    user = db.relationship('User', backref='transactions')  # Add relationship to User
    
    __table_args__ = (
        CheckConstraint('quantity > 0', name='check_quantity_positive'),
    )

# --- Helpers ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def resolve_location(loc_input):
    """
    Finds a location by exact name or matches number component.
    e.g. '100' -> matches 'C100'
    """
    # 1. Exact Match (Case-insensitive)
    loc = Location.query.filter(Location.name.ilike(loc_input)).first()
    if loc:
        return loc.id
    
    # 2. Number Match
    nums = re.findall(r'\d+', str(loc_input))
    if nums:
        input_num = nums[0]
        # Iterate all locations (efficient enough for <1000 locations)
        all_locs = Location.query.all()
        for l in all_locs:
            l_nums = re.findall(r'\d+', l.name)
            if l_nums and l_nums[0] == input_num:
                return l.id
                return l.id
    return None

def check_expiry(expiry_str):
    if not expiry_str: return ''
    try:
        # MM/YY
        parts = expiry_str.split('/')
        if len(parts) != 2: return ''
        month, year = int(parts[0]), int(parts[1])
        # Assume 20xx
        full_year = 2000 + year
        
        # Expiry date is end of month? Or start? Let's say start of that month or end.
        # Usually best is: if '01/25', it expires Jan 2025.
        # Let's compare with today.
        exp_dt = date(full_year, month, 1)
        # Next month 1st minus 1 day is end of month.
        # simpler: just compare month/year.
        
        today = date.today()
        # Construct date for expiry (1st of month)
        exp_date = date(full_year, month, 1)
        
        # Expired if this month is past? Or if today is > end of expiry month?
        # Let's say Expired if today > last day of expiry month.
        if month == 12:
            next_month = date(full_year + 1, 1, 1)
        else:
            next_month = date(full_year, month + 1, 1)
        last_day_of_expiry = next_month - timedelta(days=1)
        
        if today > last_day_of_expiry:
            return 'expired' # Red
        
        # Expiring soon (within 60 days)
        diff = (last_day_of_expiry - today).days
        if diff < 60:
            return 'expiring' # Orange
        
        return 'ok'
    except:
        return ''


# --- Routes ---

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
        
        # Get batch-level data
        batch_doc_number = data.get('doc_number')
        batch_date_str = data.get('date')
        batch_remarks = data.get('remarks')
        batch_container = data.get('container_number')
        
        # Parse date
        batch_date = None
        if batch_date_str:
            try:
                batch_date = datetime.strptime(batch_date_str, '%Y-%m-%d').date()
            except:
                batch_date = date.today()
        else:
            batch_date = date.today()
        
        try:
            for i in items:
                # Resolve Item (by ID or SKU/Name if needed, but frontend sends ID)
                item_id = i.get('item_id')
                qty = float(i.get('quantity', 0))
                pallets = int(i.get('pallets', 0)) if i.get('pallets') else None
                loc_txt = i.get('location_id') # User input text
                expiry = i.get('expiry') # User input MM/YY
                
                # Validate quantity
                if qty <= 0:
                    return jsonify({'success': False, 'message': 'Quantity must be greater than 0'}), 400
                
                # Resolve Location
                loc_id = resolve_location(loc_txt)
                if not loc_id:
                    return jsonify({'success': False, 'message': f'Location "{loc_txt}" not found'}), 400
                
                location = Location.query.get(loc_id)
                if not location:
                    return jsonify({'success': False, 'message': 'Location not found'}), 400
                
                # Check pallet capacity
                existing_inv = Inventory.query.filter_by(item_id=item_id, location_id=loc_id, expiry=expiry).first()
                if not existing_inv:
                    # New batch = new pallet
                    used_pallets = location.get_used_pallets()
                    if used_pallets >= location.max_pallets:
                        return jsonify({'success': False, 'message': f'Location "{loc_txt}" is full ({location.max_pallets} pallets max)'}), 400
                
                # Update Inventory (Batch: Item + Loc + Expiry)
                if existing_inv:
                    existing_inv.quantity += qty
                    # Update other fields if provided
                    if batch_doc_number:
                        existing_inv.doc_number = batch_doc_number
                    if batch_date:
                        existing_inv.date = batch_date
                    if pallets is not None:
                        existing_inv.pallets = (existing_inv.pallets or 0) + pallets
                    if batch_remarks:
                        existing_inv.remarks = batch_remarks
                    if batch_container:
                        existing_inv.container_number = batch_container
                    existing_inv.worker_name = current_user.username
                    # Ensure no negative stock
                    if existing_inv.quantity < 0:
                        return jsonify({'success': False, 'message': 'Resulting quantity would be negative'}), 400
                else:
                    inv = Inventory(
                        item_id=item_id, 
                        location_id=loc_id, 
                        quantity=qty, 
                        expiry=expiry,
                        doc_number=batch_doc_number,
                        date=batch_date,
                        pallets=pallets,
                        remarks=batch_remarks,
                        container_number=batch_container,
                        worker_name=current_user.username
                    )
                    db.session.add(inv)
                
                # Log Transaction
                trans = Transaction(
                    type='IN', 
                    item_id=item_id, 
                    location_id=loc_id, 
                    quantity=qty, 
                    user_id=current_user.id, 
                    expiry=expiry,
                    doc_number=batch_doc_number,
                    date=batch_date,
                    pallets=pallets,
                    remarks=batch_remarks,
                    container_number=batch_container,
                    worker_name=current_user.username
                )
                db.session.add(trans)
                
            db.session.commit()
            return jsonify({'success': True, 'message': 'Incoming Stock Added'})
        except Exception as e:
            db.session.rollback()
            import traceback
            print(f"Error in incoming: {str(e)}")
            print(traceback.format_exc())
            return jsonify({'success': False, 'message': str(e)}), 500

    # History: Show ALL with new fields
    history = Transaction.query.filter_by(type='IN').order_by(Transaction.timestamp.desc()).limit(100).all()
    return render_template('incoming.html', recent_history=history, date=date)

@app.route('/outgoing', methods=['GET', 'POST'])
@login_required
def outgoing():
    if request.method == 'POST':
        data = request.get_json()
        items = data.get('items', [])
        
        # Get batch-level data
        batch_doc_number = data.get('doc_number')
        batch_date_str = data.get('date')
        batch_remarks = data.get('remarks')
        batch_container = data.get('container_number')
        
        # Parse date
        batch_date = None
        if batch_date_str:
            try:
                batch_date = datetime.strptime(batch_date_str, '%Y-%m-%d').date()
            except:
                batch_date = date.today()
        else:
            batch_date = date.today()
        
        try:
            for i in items:
                item_id = i.get('item_id')
                qty = float(i.get('quantity', 0))
                pallets = int(i.get('pallets', 0)) if i.get('pallets') else None
                loc_txt = i.get('location_id')
                
                # Validate quantity
                if qty <= 0:
                    return jsonify({'success': False, 'message': 'Quantity must be greater than 0'}), 400
                
                loc_id = resolve_location(loc_txt)
                if not loc_id:
                    return jsonify({'success': False, 'message': f'Location "{loc_txt}" not found'}), 400
                
                # FEFO Logic: Get all batches for this item/loc, sorted by expiry string? 
                # String sort MM/YY might fail for cross-year (12/25 vs 01/26).
                # But kept simple for now or better yet, iterate and parse if needed.
                # Assuming standard valid MM/YY inputs.
                # NOTE: String sort on MM/YY is NOT chronological for years. 01/26 < 12/25 is FALSE in string ascii. 
                # ASCII: '0' < '1'. So '01/26' < '12/25'. This actually works for year WRONG.
                # '01/26' comes before '12/25' in Dictionary, which is CORRECT for months, but if years differ...
                # actually '01/26' vs '12/25'. '0' < '1'. So '01/26' is "smaller" (earlier) than '12/25'. 
                # Wait. '01/26' IS LATER than '12/25'. String sort sends '01/26' first. ERROR.
                # So we must fetch all and sort in python logic for correctness.
                
                # Validate quantity
                if qty <= 0:
                    return {'success': False, 'message': 'Quantity must be greater than 0'}, 400
                
                batches = Inventory.query.filter_by(item_id=item_id, location_id=loc_id).filter(Inventory.quantity > 0).all()
                
                # Python Sort: Parse expiry 'MM/YY'
                def parse_expiry(b):
                    if not b.expiry: return datetime.max
                    try:
                        return datetime.strptime(b.expiry, '%m/%y')
                    except:
                        return datetime.max
                        
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
                    
                    # Ensure quantity never goes negative (database constraint should catch this, but double-check)
                    if batch.quantity < 0:
                        db.session.rollback()
                        return {'success': False, 'message': 'Error: Quantity would become negative'}, 400
                    
                    if batch.quantity == 0:
                        db.session.delete(batch)

                    # Log transaction with all fields
                    trans = Transaction(
                        type='OUT', 
                        item_id=item_id, 
                        location_id=loc_id, 
                        quantity=taken, # Must be positive due to DB constraint
                        user_id=current_user.id, 
                        expiry=batch.expiry,
                        doc_number=batch_doc_number,
                        date=batch_date,
                        pallets=pallets,
                        remarks=batch_remarks,
                        container_number=batch_container,
                        worker_name=current_user.username
                    )
                    db.session.add(trans)
            
            db.session.commit()
            return jsonify({'success': True, 'message': 'Outgoing Stock Processed'})
        except Exception as e:
            db.session.rollback()
            import traceback
            print(f"Error in outgoing: {str(e)}")
            print(traceback.format_exc())
            return jsonify({'success': False, 'message': str(e)}), 500

    history = Transaction.query.filter_by(type='OUT').order_by(Transaction.timestamp.desc()).limit(100).all()
    return render_template('outgoing.html', recent_history=history, date=date)


# --- Admin Routes ---

@app.route('/admin/db')
@login_required
def admin_db():
    if not current_user.is_admin():
        flash('Access denied.')
        return redirect(url_for('dashboard'))
    
    # Get all table names
    tables = sorted(list(db.metadata.tables.keys()))
    
    current_table = request.args.get('table')
    data = []
    columns = []
    
    if current_table:
        if current_table not in tables:
            flash('Invalid table selected.')
            return redirect(url_for('admin_db'))
        
        # Raw SQL query for safety (read only view)
        try:
             # Use SQLAlchemy text() for safe execution, but table name can't be bound easily in all SQL dialects as identifier.
             # Since we validated `current_table` against metadata keys, it is safe to f-string here.
            from sqlalchemy import text
            sql = text(f"SELECT * FROM {current_table} LIMIT 100")
            result = db.session.execute(sql)
            columns = result.keys()
            data = [dict(zip(columns, row)) for row in result]
        except Exception as e:
            flash(f'Error querying table: {str(e)}')
            
    return render_template('admin_db.html', tables=tables, current_table=current_table, data=data, columns=columns)

@app.route('/admin/items', methods=['GET', 'POST'])
@login_required
def admin_items():
    # Only admins can access
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        action = request.form.get('action')
        
        # --- File Upload ---
        if 'file' in request.files:
            file = request.files['file']
            if file and (file.filename.endswith('.xlsx') or file.filename.endswith('.xls')):
                try:
                    df = pd.read_excel(file)
                    # Helper to clean strings
                    def clean(x): return str(x).strip() if pd.notna(x) else ''
                    
                    count = 0
                    for _, row in df.iterrows():
                        sku = clean(row.get('Item Code', '') or row.get('SKU', ''))
                        if not sku or sku == 'nan': continue
                        
                        name = clean(row.get('Description', '') or row.get('Name', 'Unknown'))
                        
                        item = Item.query.filter_by(sku=sku).first()
                        if not item:
                            item = Item(
                                sku=sku, 
                                name=name, 
                                description=name,
                                brand=clean(row.get('Brand', '')),
                                packing=clean(row.get('Packing', '')),
                                weight=row.get('Weight', 0.0) if pd.notna(row.get('Weight')) else 0.0,
                                uom=clean(row.get('UOM', ''))
                            )
                            db.session.add(item)
                            count += 1
                        else:
                            # Update existing
                            item.name = name
                            item.description = name
                            item.brand = clean(row.get('Brand', ''))
                            item.packing = clean(row.get('Packing', ''))
                            item.weight = row.get('Weight', 0.0) if pd.notna(row.get('Weight')) else 0.0
                            item.uom = clean(row.get('UOM', ''))
                    db.session.commit()
                    flash(f'Successfully imported/updated {count} items.')
                except Exception as e:
                    db.session.rollback()
                    flash(f'Error processing file: {str(e)}')
            return redirect(url_for('admin_items'))

        # --- Manual Actions ---
        if action == 'add':
            sku = request.form.get('sku')
            if Item.query.filter_by(sku=sku).first():
                flash('Item with this SKU already exists.')
            else:
                try:
                    item = Item(
                        sku=sku,
                        name=request.form.get('name'),
                        description=request.form.get('description'),
                        brand=request.form.get('brand'),
                        packing=request.form.get('packing'),
                        weight=float(request.form.get('weight') or 0),
                        uom=request.form.get('uom')
                    )
                    db.session.add(item)
                    db.session.commit()
                    flash('Item added successfully.')
                except Exception as e:
                    flash(f'Error adding item: {e}')

        elif action == 'edit':
            item_id = request.form.get('item_id')
            item = Item.query.get(item_id)
            if item:
                item.sku = request.form.get('sku')
                item.name = request.form.get('name')
                item.description = request.form.get('description')
                item.brand = request.form.get('brand')
                item.packing = request.form.get('packing')
                item.weight = float(request.form.get('weight') or 0)
                item.uom = request.form.get('uom')
                db.session.commit()
                flash('Item updated.')

        elif action == 'delete':
            item_id = request.form.get('item_id')
            item = Item.query.get(item_id)
            if item:
                # Cleanup Inventory first to avoid FK error
                Inventory.query.filter_by(item_id=item.id).delete()
                # Transactions: Set item_id to null or keep? 
                # SQLAlchemy default is usually NO ACTION or CASCADE depending on setup.
                # To be safe, nullify transaction references or delete them. 
                # Let's simple delete the item and let FKs decide (if models set up right)
                # But our models don't specify cascade. So manually handle:
                # Actually Transaction.item_id is nullable. So we can just set it to None if we want history,
                # OR if we want to delete history. Usually deleting item deletes history in simple apps.
                # Let's keep history but nullify ID? No, difficult to query.
                # Let's just try deleting. If it fails, we handle it.
                # Safe approach: Delete inventory.
                db.session.delete(item)
                db.session.commit()
                flash('Item deleted.')
                
        return redirect(url_for('admin_items'))
    

    # Pagination simplified: Just show all for now, or simple limit
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip()
    
    query = Item.query
    if q:
        query = query.filter(db.or_(
            Item.name.ilike(f'%{q}%'),
            Item.sku.ilike(f'%{q}%'),
            Item.brand.ilike(f'%{q}%')
        ))
        
    items = query.paginate(page=page, per_page=50)
    return render_template('admin_items.html', items=items, q=q)

@app.route('/admin/locations', methods=['GET', 'POST'])
@login_required
def admin_locations():
    # Only admins can access
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        action = request.form.get('action')

        # --- File Upload ---
        if 'file' in request.files:
            file = request.files['file']
            if file and (file.filename.endswith('.xlsx') or file.filename.endswith('.xls')):
                try:
                    df = pd.read_excel(file)
                    count = 0
                    for _, row in df.iterrows():
                        name = str(row.get('Loc', '')).strip()
                        if not name or name == 'nan': continue
                        
                        if name:
                            loc = Location.query.filter_by(name=name).first()
                            if not loc:
                                loc = Location(name=name, x=0, y=0)
                                db.session.add(loc)
                                count += 1
                    db.session.commit()
                    flash(f'Successfully imported {count} locations.')
                except Exception as e:
                    flash(f'Error importing: {str(e)}')
            return redirect(url_for('admin_locations'))
        
        # --- Manual Actions ---
        if action == 'add':
            name = request.form.get('name')
            if Location.query.filter_by(name=name).first():
                flash('Location already exists.')
            else:
                try:
                    loc = Location(
                        name=name,
                        x=int(request.form.get('x') or 0),
                        y=int(request.form.get('y') or 0)
                    )
                    db.session.add(loc)
                    db.session.commit()
                    flash('Location added.')
                except Exception as e:
                    flash(f'Error: {e}')
        
        elif action == 'edit':
            loc_id = request.form.get('loc_id')
            loc = Location.query.get(loc_id)
            if loc:
                loc.name = request.form.get('name')
                loc.x = int(request.form.get('x') or 0)
                loc.y = int(request.form.get('y') or 0)
                db.session.commit()
                flash('Location updated.')

        elif action == 'delete':
            loc_id = request.form.get('loc_id')
            loc = Location.query.get(loc_id)
            if loc:
                # Cleanup Inventory first
                Inventory.query.filter_by(location_id=loc.id).delete()
                db.session.delete(loc)
                db.session.commit()
                flash('Location deleted.')
        
        return redirect(url_for('admin_locations'))

    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip()
    
    query = Location.query
    if q:
        query = query.filter(Location.name.ilike(f'%{q}%'))
        
    locations = query.paginate(page=page, per_page=50)
    locations = query.paginate(page=page, per_page=50)
    return render_template('admin_locations.html', locations=locations, q=q)

@app.route('/dashboard')
@login_required
def dashboard():
    # --- Stats ---
    # 1. Total Inventory items (active batches)
    total_items = Inventory.query.filter(Inventory.quantity > 0).count()
    
    # 2. Total Locations
    total_locations = Location.query.count()
    
    # 3. Total Value
    # Using python sum for simpler logic, though SQL is faster for huge data
    inventory = Inventory.query.filter(Inventory.quantity > 0).all()
    total_value = sum((inv.quantity * (inv.item.price or 0)) for inv in inventory)
    
    # 4. Low Stock Items
    # Aggregate quantity per item
    # This is a bit heavy, optimizing for MVP: Fetch all items, verify stock
    # For large datasets, use GROUP BY query
    from sqlalchemy import func
    stock_levels = db.session.query(
        Item.id, Item.name, Item.min_stock, func.sum(Inventory.quantity)
    ).outerjoin(Inventory).group_by(Item.id).all()
    
    low_stock_items = []
    for s in stock_levels:
        item_id, item_name, min_stock, total_qty = s
        total_qty = total_qty or 0
        if total_qty < (min_stock or 0):
             low_stock_items.append({'name': item_name, 'qty': total_qty, 'min': min_stock})

    # 5. Expiry (Expiring in 30 days or less)
    # Using existing logic for expiry check
    expiring_items = []
    today_date = date.today()
    for inv in inventory: # reusing fetched inventory
        check = check_expiry(inv.expiry) # returns 'expired', 'expiring', or 'ok'
        if check in ['expired', 'expiring']:
            expiring_items.append(inv)
            
    # 6. Chart Data (Last 30 Days Movement)
    # Group transactions by date and type
    last_30 = datetime.now() - timedelta(days=30)
    txs = Transaction.query.filter(Transaction.timestamp >= last_30).all()
    
    chart_data = {}
    # Initialize dict for last 30 days
    for i in range(31):
        d = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        chart_data[d] = {'in': 0, 'out': 0}
        
    for t in txs:
        d_str = t.timestamp.strftime('%Y-%m-%d')
        if d_str in chart_data:
            chart_data[d_str][t.type.lower()] += 1
            
    # Sort for display
    dates = sorted(chart_data.keys())
    data_in = [chart_data[d]['in'] for d in dates]
    data_out = [chart_data[d]['out'] for d in dates]

    return render_template('dashboard.html', 
                           total_items=total_items, 
                           total_locations=total_locations,
                           total_value=total_value,
                           low_stock_items=low_stock_items,
                           expiring_items=expiring_items,
                           items=inventory, # legacy
                           locations=[], # legacy map removed
                           chart_dates=dates,
                           chart_in=data_in,
                           chart_out=data_out)


@app.route('/logs')
@login_required
def logs():
    # Show all transactions, newest first
    # Join queries are implicit with relationships, but let's be sure to eager load if performance matters. 
    # For now, simple access is fine for <10k rows.
    logs = Transaction.query.order_by(Transaction.timestamp.desc()).limit(500).all()
    return render_template('logs.html', logs=logs)

@app.route('/warehouse')
@login_required
def warehouse():
    # Show only locations that have items (quantity > 0)
    # Get all locations with inventory
    locations_with_items = db.session.query(Location).join(Inventory).filter(Inventory.quantity > 0).distinct().order_by(Location.name).all()
    
    # Calculate pallet usage for each location
    location_data = []
    for loc in locations_with_items:
        used_pallets = loc.get_used_pallets()
        free_pallets = loc.get_free_pallets()
        # Get inventory items for this location (only with quantity > 0)
        inventory_items = [inv for inv in loc.inventory if inv.quantity > 0]
        active_item_count = len(inventory_items)
        # Only include if location has items
        if used_pallets > 0:
            location_data.append({
                'location': loc,
                'used_pallets': used_pallets,
                'free_pallets': free_pallets,
                'max_pallets': loc.max_pallets,
                'usage_percent': (used_pallets / loc.max_pallets * 100) if loc.max_pallets > 0 else 0,
                'active_item_count': active_item_count,
                'inventory_items': inventory_items
            })
    
    return render_template('warehouse.html', location_data=location_data)

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
def admin_users():
    # Only admins can access
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add':
            username = request.form.get('username')
            password = request.form.get('password')
            role = request.form.get('role', 'worker')
            
            if User.query.filter_by(username=username).first():
                flash('Username already exists.')
            else:
                try:
                    user = User(username=username, role=role)
                    user.set_password(password)
                    db.session.add(user)
                    db.session.commit()
                    flash('User created successfully.')
                except Exception as e:
                    flash(f'Error creating user: {e}')
        
        elif action == 'edit':
            user_id = request.form.get('user_id')
            user = User.query.get(user_id)
            if user:
                user.role = request.form.get('role', user.role)
                password = request.form.get('password')
                if password:
                    user.set_password(password)
                db.session.commit()
                flash('User updated.')
        
        elif action == 'delete':
            user_id = request.form.get('user_id')
            user = User.query.get(user_id)
            if user and user.id != current_user.id:  # Prevent self-deletion
                user.active = False
                db.session.commit()
                flash('User deactivated.')
            elif user and user.id == current_user.id:
                flash('Cannot deactivate your own account.')
        
        return redirect(url_for('admin_users'))
    
    users = User.query.filter(User.active == True).all()
    return render_template('admin_users.html', users=users)

# --- API for Autocomplete ---
@app.route('/api/items/search')
@login_required
def search_items():
    q = request.args.get('q', '')
    if not q: return {'results': []}
    items = Item.query.filter(db.or_(Item.name.ilike(f'%{q}%'), Item.sku.ilike(f'%{q}%'))).limit(10).all()
    return {'results': [{'id': i.id, 'text': f"{i.name} ({i.sku})", 'brand': i.brand} for i in items]}

@app.route('/api/item/<int:item_id>/locations')
@login_required
def get_item_locations(item_id):
    # Find inventory for this item with quantity > 0
    # Group by location? Or just list all batches?
    # Outgoing page expects: name, quantity.
    # If we have batches with Expiry, we need to sum them per location OR show batches?
    # The current outgoing.html JS expects: `loc.name` and `loc.quantity`.
    # It selects a LOCATION, then user enters Qty. 
    # So we should group by Location and sum quantity.
    
    inventory = Inventory.query.filter_by(item_id=item_id).filter(Inventory.quantity > 0).all()
    
    # helper to group
    locs = {}
    for inv in inventory:
        lname = inv.location.name
        if lname not in locs:
            locs[lname] = 0
        locs[lname] += inv.quantity
        
    results = [{'name': k, 'quantity': v} for k, v in locs.items()]
    return {'locations': results}

@app.route('/reports')
@login_required
def reports():
    query = Transaction.query

    # Filters
    search_term = request.args.get('search', '').strip()
    filter_type = request.args.get('type', 'all') # all, in, out
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    
    # New Filters
    brand_filter = request.args.get('brand', '').strip()
    min_qty = request.args.get('min_qty', '')
    max_qty = request.args.get('max_qty', '')

    query = Transaction.query.join(Item) # Join for searching/filtering by item props

    if filter_type == 'in':
        query = query.filter(Transaction.type == 'IN')
    elif filter_type == 'out':
        query = query.filter(Transaction.type == 'OUT')



    if start_date:
        try:
            s_dt = datetime.strptime(start_date, '%Y-%m-%d')
            query = query.filter(Transaction.timestamp >= s_dt)
        except: pass
    
    if end_date:
        try:
            # End of the selected day
            e_dt = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(Transaction.timestamp < e_dt)
        except: pass

    # Brand Filter
    if brand_filter:
        query = query.filter(Item.brand.ilike(f'%{brand_filter}%'))

    # Quantity Range
    if min_qty:
        try:
            query = query.filter(db.func.abs(Transaction.quantity) >= float(min_qty))
        except: pass
    
    if max_qty:
        try:
            query = query.filter(db.func.abs(Transaction.quantity) <= float(max_qty))
        except: pass

    if search_term:
        term = f"%{search_term}%"
        query = query.join(Location, Transaction.location_id == Location.id)\
                     .filter(
                         db.or_(
                             Item.name.ilike(term),
                             Item.sku.ilike(term),
                             Location.name.ilike(term),
                             Transaction.remarks.ilike(term),
                             Transaction.doc_number.ilike(term)
                         )
                     )


    # Order by newest first
    transactions = query.order_by(Transaction.timestamp.desc()).limit(500).all()

    # Export Logic
    if request.args.get('export') == 'csv':
        selected_cols = request.args.get('cols', '').split(',')
        # Define all available columns map
        all_cols_map = {
            'date': 'Date',
            'time': 'Time',
            'type': 'Type',
            'doc': 'Doc Number',
            'sku': 'SKU',
            'name': 'Item Name',
            'brand': 'Brand',
            'loc': 'Location',
            'qty': 'Quantity',
            'plts': 'Pallets',
            'expiry': 'Expiry',
            'user': 'User',
            'remarks': 'Remarks'
        }
        
        # If no specific cols requested, use all
        if not selected_cols or selected_cols == ['']:
            active_cols = all_cols_map.values()
        else:
            active_cols = [all_cols_map[c] for c in selected_cols if c in all_cols_map]

        data = []
        for t in transactions:
            row = {
                'Date': t.timestamp.strftime('%Y-%m-%d'),
                'Time': t.timestamp.strftime('%H:%M'),
                'Type': t.type,
                'Doc Number': t.doc_number,
                'SKU': t.item.sku,
                'Item Name': t.item.name,
                'Brand': t.item.brand,
                'Location': t.location.name,
                'Quantity': t.quantity,
                'Pallets': t.pallets,
                'Expiry': t.expiry,
                'User': t.worker_name or (t.user.username if t.user else 'System'),
                'Remarks': t.remarks
            }
            # Filter row keys
            filtered_row = {k: v for k, v in row.items() if k in active_cols}
            data.append(filtered_row)
        
        # DataFrame re-ordering to match display order if needed, or just dict keys
        df = pd.DataFrame(data)
        
        # Reorder columns to match selection (optional but nice)
        # Ensure only columns that exist in data are selected
        final_cols = [c for c in active_cols if c in df.columns]
        if final_cols:
            df = df[final_cols]
        
        # Create CSV in memory
        from io import BytesIO
        output = BytesIO()
        df.to_csv(output, index=False)
        output.seek(0)
        
        return Response(
            output,
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment;filename=inventory_report_{date.today()}.csv"}
        )

    return render_template('reports.html', transactions=transactions, today=date.today())

# API Route for Details
@app.route('/api/location/<location_id>')
@app.route('/api/location/<location_id>/inventory')
@login_required
def get_location_inventory(location_id):
    try:
        # Convert location_id to integer if possible
        try:
            loc_id = int(location_id)
        except ValueError:
            return jsonify({'error': 'Invalid location ID'}), 400
        
        # Fetch all inventory items for this location
        location = Location.query.get(loc_id)
        if not location:
            return jsonify({'error': 'Location not found'}), 404
        
        # Get inventory with eager loading to avoid relationship issues
        inventory = db.session.query(Inventory).filter_by(location_id=loc_id).filter(Inventory.quantity > 0).all()
        results = []
        for inv in inventory:
            # Safely access item relationship
            if inv.item:
                results.append({
                    'item_sku': inv.item.sku or '',
                    'item_name': inv.item.name or '',
                    'quantity': float(inv.quantity) if inv.quantity else 0,
                    'expiry': inv.expiry or '',
                    'packing': inv.item.packing or '',
                    'brand': inv.item.brand or '',
                    'pallets': inv.pallets or 0,
                    'date': inv.date.strftime('%Y-%m-%d') if inv.date else '',
                    'worker_name': inv.worker_name or ''
                })
        
        # Include pallet information
        used_pallets = location.get_used_pallets()
        free_pallets = location.get_free_pallets()
        
        return jsonify({
            'inventory': results,
            'location': {
                'name': location.name or '',
                'used_pallets': used_pallets,
                'free_pallets': free_pallets,
                'max_pallets': location.max_pallets or 28
            }
        })
    except Exception as e:
        import traceback
        print(f"Error in get_location_inventory: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': f'Server error: {str(e)}'}), 500

# --- Initialization ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create Admin if not exists
        if not User.query.filter_by(username='admin').first():
            user = User(username='admin', role='admin')
            user.set_password('admin')
            db.session.add(user)
            db.session.commit()
            print("Created admin user (username: admin, password: admin)")
            print("⚠️  WARNING: Change default admin password in production!")
    
    # --- Template Helpers ---
    @app.context_processor
    def utility_processor():
        return dict(check_expiry=check_expiry, timedelta=timedelta)

    # Use environment variable for debug mode, default to True for development
    debug_mode = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    port = int(os.environ.get('PORT', 5001))
    
    if debug_mode:
        print("⚠️  WARNING: Debug mode is enabled. Disable in production!")
        print("📝 Template auto-reload is enabled. Changes will be picked up automatically.")
    
    # Enable template auto-reload in debug mode
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.run(debug=debug_mode, port=port, use_reloader=True)
