
from app import app, db, User, Item, Location
import pandas as pd
import os

def seed_data():
    with app.app_context():
        db.create_all()
        
        # Seed Items from Excel
        items_path = 'items.xlsx'
        if not os.path.exists(items_path):
            items_path = '../items.xlsx'
            
        if os.path.exists(items_path):
            try:
                df = pd.read_excel(items_path)
                print(f"Seeding {len(df)} items from Excel...")
                for _, row in df.iterrows():
                    sku = str(row.get('Item Code', '')).strip()
                    if not sku or sku == 'nan': continue
                    
                    if not Item.query.filter_by(sku=sku).first():
                        item = Item(
                            sku=sku,
                            name=str(row.get('Description', 'Unknown')).strip(),
                            description=str(row.get('Description', '')).strip(),
                            brand=str(row.get('Brand', '')).strip(),
                            packing=str(row.get('Packing', '')).strip(),
                            weight=row.get('Weight', 0.0) if pd.notna(row.get('Weight')) else 0.0,
                            uom=str(row.get('UOM', '')).strip()
                        )
                        db.session.add(item)
                db.session.commit()
            except Exception as e:
                print(f"Error reading items: {e}")
        
        # Seed Locations from Excel
        locs_path = 'locs.xlsx'
        if not os.path.exists(locs_path):
            locs_path = '../locs.xlsx'

        if os.path.exists(locs_path):
            try:
                df = pd.read_excel(locs_path)
                print(f"Seeding {len(df)} locations from Excel...")
                for _, row in df.iterrows():
                    name = str(row.get('Loc', '')).strip()
                    if not name or name == 'nan': continue
                    
                    if not Location.query.filter_by(name=name).first():
                        loc = Location(
                            name=name,
                            x=0, # Default X
                            y=0  # Default Y
                        )
                        db.session.add(loc)
                db.session.commit()
            except Exception as e:
                print(f"Error reading locations: {e}")
                
        print("Seeding Complete.")

if __name__ == '__main__':
    seed_data()
