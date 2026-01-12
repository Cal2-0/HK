# HK - Import/Export Stock Management System

## Overview
HK is a robust, web-based inventory management system designed for companies handling import and export of stock. It provides a centralized platform to track inventory levels, monitor stock movements, manage warehouse locations, and generate comprehensive reports.

## Key Features

### 📦 Inventory Management
- **Incoming Stock**: Log inbound shipments with detailed information (Item Name, ID, Quantity, Location, Min Stock, Price).
- **Outgoing Stock**: Track outbound orders and reduce inventory levels accordingly.
- **Stock Alerts**: Automatic notifications for low stock levels and expiring items.

### 📊 Dashboard & Analytics
- **Real-time Overview**: Visual dashboard displaying total inventory value, recent movements, and critical alerts.
- **Stock Movement Charts**: Visualize inventory trends over time.
- **Warehouse Map**: Interactive map showing item locations within the warehouse.

### 📑 Reports & Auditing
- **Transaction History**: Complete log of all incoming and outgoing transactions.
- **Current Stock Snapshot**: Real-time view of current inventory levels.
- **Export Options**: Export reports to generic PDF and CSV formats for external processing.
- **Audit Logs**: Comprehensive tracking of user actions for security and accountability.

### 🛠 Administrative Tools
- **User Management**: Role-based access control (Admin/User).
- **Data Import**: Bulk import inventory data via Excel/CSV files.
- **Location Management**: Manage warehouse zones and storage bins.

## Technology Stack
- **Backend**: Python (Flask)
- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)
- **Database**: SQLite / Supabase (PostgreSQL)
- **Deployment**: Render / Local Hosting

## Setup & Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd hk-inventory-system
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment**
   - Set up `.env` file with necessary API keys and Database URLs.

4. **Initialize Database**
   ```bash
   flask db upgrade
   ```

5. **Run the Application**
   ```bash
   python app.py
   ```

## License
[Proprietary/Internal Use Only]