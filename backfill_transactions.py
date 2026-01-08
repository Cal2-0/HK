
from app import app, db, Inventory, Transaction, User
import datetime

def backfill():
    """
    Creates 'Opening Balance' transactions for any Inventory items 
    that do not appear to have a corresponding entry in the Transaction log.
    This fixes the 'Missing Reports' issue for items imported before the logging fix.
    """
    with app.app_context():
        print("🔍 Scanning Inventory vs Transactions...")
        
        # Get all current inventory
        inventory = Inventory.query.all()
        
        # Get all IN transactions
        # This is a heuristic. Ideally we match exactly, but for backfill 
        # we just want to ensure everything currently in stock has an 'IN' record.
        # Since we can't easily match 1-to-1 without unique IDs, we'll check 
        # if the TOTAL "IN" qty for an item/loc matches the CURRENT qty.
        
        count = 0
        user = User.query.filter_by(username='admin').first()
        user_id = user.id if user else 1
        
        for inv in inventory:
            if inv.quantity <= 0: continue
            
            # Check if any transaction exists for this item at this location
            # A simple heuristic: If no transactions at all for this item+loc, create one.
            exists = Transaction.query.filter_by(
                item_id=inv.item_id, 
                location_id=inv.location_id
            ).first()
            
            if not exists:
                print(f"➕ Creating missing transaction for {inv.item.sku} at {inv.location.name} (Qty: {inv.quantity})")
                
                t = Transaction(
                    type='IN',
                    item_id=inv.item_id,
                    location_id=inv.location_id,
                    quantity=inv.quantity,
                    user_id=user_id,
                    timestamp=datetime.datetime.utcnow(),
                    expiry=inv.expiry,
                    worker_name='System',
                    remarks="Opening Balance (Backfill)"
                )
                db.session.add(t)
                count += 1
        
        if count > 0:
            db.session.commit()
            print(f"✅ Successfully backfilled {count} missing transaction records!")
        else:
            print("✅ No missing transactions found. Reports should be accurate.")

if __name__ == "__main__":
    backfill()
