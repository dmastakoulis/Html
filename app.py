from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key-here-change-in-production'

DATABASE = 'database/crm.db'

# Database helper functions
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database with tables"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('employee', 'manager', 'admin')),
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Customers table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            company TEXT,
            category TEXT CHECK(category IN ('Lead', 'Active', 'Inactive', 'Cancelled')) DEFAULT 'Lead',
            is_active INTEGER DEFAULT 1,
            employee_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (employee_id) REFERENCES users(id)
        )
    ''')
    
    # Contacts/Interactions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            employee_id INTEGER NOT NULL,
            contact_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            notes TEXT,
            no_response INTEGER DEFAULT 0,
            FOREIGN KEY (customer_id) REFERENCES customers(id),
            FOREIGN KEY (employee_id) REFERENCES users(id)
        )
    ''')
    
    # Create default admin user if not exists
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        hashed_password = generate_password_hash('admin123')
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ('admin', hashed_password, 'admin')
        )
        
        # Create sample employee
        hashed_password = generate_password_hash('employee123')
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ('employee', hashed_password, 'employee')
        )
        
        # Create sample manager
        hashed_password = generate_password_hash('manager123')
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ('manager', hashed_password, 'manager')
        )
    
    conn.commit()
    conn.close()

# Authentication decorator
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    from functools import wraps
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] not in roles:
                flash('You do not have permission to access this page')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        if session['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif session['role'] == 'manager':
            return redirect(url_for('manager_dashboard'))
        else:
            return redirect(url_for('employee_dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ? AND is_active = 1', 
            (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash(f'Welcome, {username}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login_form.html', username=request.form.get('username', ''))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password2 = request.form['password2']
        
        if password != password2:
            flash('Passwords do not match')
            return render_template('register_form.html', username=username)
        
        hashed_password = generate_password_hash(password)
        
        try:
            conn = get_db()
            conn.execute(
                'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                (username, hashed_password, 'employee')
            )
            conn.commit()
            conn.close()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists')
            return render_template('register_form.html', username=username)
    
    return render_template('register_form.html', username='')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out')
    return redirect(url_for('index'))

# Employee routes
@app.route('/employee/dashboard')
@login_required
@role_required(['employee', 'manager'])
def employee_dashboard():
    conn = get_db()
    
    # Get statistics
    total_customers = conn.execute(
        'SELECT COUNT(*) as count FROM customers WHERE employee_id = ? AND is_active = 1',
        (session['user_id'],)
    ).fetchone()['count']
    
    # Contacts this month
    contacts_month = conn.execute('''
        SELECT COUNT(*) as count FROM contacts 
        WHERE employee_id = ? AND date(contact_date) >= date('now', 'start of month')
    ''', (session['user_id'],)).fetchone()['count']
    
    # Contacts this week
    contacts_week = conn.execute('''
        SELECT COUNT(*) as count FROM contacts 
        WHERE employee_id = ? AND date(contact_date) >= date('now', '-6 days')
    ''', (session['user_id'],)).fetchone()['count']
    
    # Contacts today
    contacts_today = conn.execute('''
        SELECT COUNT(*) as count FROM contacts 
        WHERE employee_id = ? AND date(contact_date) = date('now')
    ''', (session['user_id'],)).fetchone()['count']
    
    conn.close()
    
    stats = {
        'total_customers': total_customers,
        'contacts_month': contacts_month,
        'contacts_week': contacts_week,
        'contacts_today': contacts_today
    }
    
    return render_template('employee_dashboard.html', stats=stats)

@app.route('/customers')
@login_required
@role_required(['employee', 'manager'])
def customers():
    conn = get_db()
    
    if session['role'] == 'manager':
        customers = conn.execute('''
            SELECT c.*, u.username as employee_name 
            FROM customers c 
            LEFT JOIN users u ON c.employee_id = u.id
            WHERE c.is_active = 1
            ORDER BY c.created_at DESC
        ''').fetchall()
    else:
        customers = conn.execute('''
            SELECT * FROM customers 
            WHERE employee_id = ? AND is_active = 1
            ORDER BY created_at DESC
        ''', (session['user_id'],)).fetchall()
    
    conn.close()
    return render_template('customers.html', customers=customers)

@app.route('/customers/add', methods=['GET', 'POST'])
@login_required
@role_required(['employee', 'manager'])
def add_customer():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form.get('email', '')
        phone = request.form.get('phone', '')
        company = request.form.get('company', '')
        category = request.form.get('category', 'Lead')
        
        conn = get_db()
        conn.execute('''
            INSERT INTO customers (name, email, phone, company, category, employee_id)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (name, email, phone, company, category, session['user_id']))
        conn.commit()
        conn.close()
        
        flash('Customer added successfully!')
        return redirect(url_for('customers'))
    
    return render_template('add_customer.html')

@app.route('/customers/edit/<int:customer_id>', methods=['GET', 'POST'])
@login_required
@role_required(['employee', 'manager'])
def edit_customer(customer_id):
    conn = get_db()
    
    if request.method == 'POST':
        name = request.form['name']
        email = request.form.get('email', '')
        phone = request.form.get('phone', '')
        company = request.form.get('company', '')
        category = request.form.get('category', 'Lead')
        
        conn.execute('''
            UPDATE customers 
            SET name = ?, email = ?, phone = ?, company = ?, category = ?
            WHERE id = ? AND (employee_id = ? OR ?)
        ''', (name, email, phone, company, category, customer_id, session['user_id'], session['role'] == 'manager'))
        conn.commit()
        conn.close()
        
        flash('Customer updated successfully!')
        return redirect(url_for('customers'))
    
    customer = conn.execute(
        'SELECT * FROM customers WHERE id = ? AND (employee_id = ? OR ?)',
        (customer_id, session['user_id'], session['role'] == 'manager')
    ).fetchone()
    conn.close()
    
    if not customer:
        flash('Customer not found')
        return redirect(url_for('customers'))
    
    return render_template('edit_customer.html', customer=customer)

@app.route('/customers/delete/<int:customer_id>')
@login_required
@role_required(['employee', 'manager'])
def delete_customer(customer_id):
    conn = get_db()
    conn.execute(
        'UPDATE customers SET is_active = 0 WHERE id = ? AND (employee_id = ? OR ?)',
        (customer_id, session['user_id'], session['role'] == 'manager')
    )
    conn.commit()
    conn.close()
    
    flash('Customer deactivated successfully!')
    return redirect(url_for('customers'))

@app.route('/customers/<int:customer_id>/contacts')
@login_required
@role_required(['employee', 'manager'])
def customer_contacts(customer_id):
    conn = get_db()
    
    customer = conn.execute(
        'SELECT * FROM customers WHERE id = ? AND (employee_id = ? OR ?)',
        (customer_id, session['user_id'], session['role'] == 'manager')
    ).fetchone()
    
    if not customer:
        flash('Customer not found')
        return redirect(url_for('customers'))
    
    contacts = conn.execute('''
        SELECT c.*, u.username as employee_name
        FROM contacts c
        JOIN users u ON c.employee_id = u.id
        WHERE c.customer_id = ?
        ORDER BY c.contact_date DESC
    ''', (customer_id,)).fetchall()
    
    conn.close()
    
    return render_template('customer_contacts.html', customer=customer, contacts=contacts)

@app.route('/customers/<int:customer_id>/add_contact', methods=['GET', 'POST'])
@login_required
@role_required(['employee', 'manager'])
def add_contact(customer_id):
    if request.method == 'POST':
        notes = request.form['notes']
        no_response = 1 if request.form.get('no_response') else 0
        
        conn = get_db()
        conn.execute('''
            INSERT INTO contacts (customer_id, employee_id, notes, no_response)
            VALUES (?, ?, ?, ?)
        ''', (customer_id, session['user_id'], notes, no_response))
        conn.commit()
        conn.close()
        
        flash('Contact added successfully!')
        return redirect(url_for('customer_contacts', customer_id=customer_id))
    
    conn = get_db()
    customer = conn.execute(
        'SELECT * FROM customers WHERE id = ?',
        (customer_id,)
    ).fetchone()
    conn.close()
    
    return render_template('add_contact.html', customer=customer)

# Manager routes
@app.route('/manager/dashboard')
@login_required
@role_required(['manager'])
def manager_dashboard():
    conn = get_db()
    
    # Total statistics
    total_customers = conn.execute('SELECT COUNT(*) as count FROM customers WHERE is_active = 1').fetchone()['count']
    total_employees = conn.execute("SELECT COUNT(*) as count FROM users WHERE role = 'employee' AND is_active = 1").fetchone()['count']
    total_contacts_month = conn.execute(
        "SELECT COUNT(*) as count FROM contacts WHERE date(contact_date) >= date('now', 'start of month')"
    ).fetchone()['count']
    
    # Customers by category
    categories = conn.execute('''
        SELECT category, COUNT(*) as count 
        FROM customers 
        WHERE is_active = 1
        GROUP BY category
    ''').fetchall()
    
    conn.close()
    
    stats = {
        'total_customers': total_customers,
        'total_employees': total_employees,
        'total_contacts_month': total_contacts_month,
        'categories': categories
    }
    
    return render_template('manager_dashboard.html', stats=stats)

@app.route('/manager/employee_stats')
@login_required
@role_required(['manager'])
def employee_stats():
    period = request.args.get('period', '30')  # days
    
    conn = get_db()
    stats = conn.execute('''
        SELECT 
            u.username,
            COUNT(DISTINCT c.customer_id) as total_contacts,
            COUNT(DISTINCT cu.id) as total_customers
        FROM users u
        LEFT JOIN contacts c ON u.id = c.employee_id 
            AND date(c.contact_date) >= date('now', '-' || ? || ' days')
        LEFT JOIN customers cu ON u.id = cu.employee_id AND cu.is_active = 1
        WHERE u.role = 'employee' AND u.is_active = 1
        GROUP BY u.id, u.username
        ORDER BY total_contacts DESC
    ''', (period,)).fetchall()
    
    conn.close()
    
    return render_template('employee_stats.html', stats=stats, period=period)

@app.route('/manager/inactive_customers')
@login_required
@role_required(['manager'])
def inactive_customers():
    days = request.args.get('days', '30')
    
    conn = get_db()
    customers = conn.execute('''
        SELECT 
            c.id,
            c.name,
            c.email,
            c.phone,
            c.company,
            c.category,
            u.username as employee_name,
            MAX(ct.contact_date) as last_contact
        FROM customers c
        LEFT JOIN contacts ct ON c.id = ct.customer_id
        JOIN users u ON c.employee_id = u.id
        WHERE c.is_active = 1
        GROUP BY c.id
        HAVING last_contact IS NULL 
            OR date(last_contact) < date('now', '-' || ? || ' days')
        ORDER BY last_contact ASC
    ''', (days,)).fetchall()
    
    conn.close()
    
    return render_template('inactive_customers.html', customers=customers, days=days)

@app.route('/manager/no_response_customers')
@login_required
@role_required(['manager'])
def no_response_customers():
    attempts = request.args.get('attempts', '3')
    
    conn = get_db()
    customers = conn.execute('''
        SELECT 
            c.id,
            c.name,
            c.email,
            c.phone,
            c.company,
            u.username as employee_name,
            COUNT(ct.id) as no_response_count
        FROM customers c
        JOIN (
            SELECT customer_id, MAX(contact_date) as last_contact
            FROM contacts
            GROUP BY customer_id
        ) lc ON c.id = lc.customer_id
        JOIN contacts ct ON c.id = ct.customer_id 
            AND ct.contact_date > date(lc.last_contact, '-' || ? || ' days')
        JOIN users u ON c.employee_id = u.id
        WHERE ct.no_response = 1 AND c.is_active = 1
        GROUP BY c.id
        HAVING no_response_count >= ?
        ORDER BY no_response_count DESC
    ''', (attempts, attempts)).fetchall()
    
    conn.close()
    
    return render_template('no_response_customers.html', customers=customers, attempts=attempts)

# Admin routes
@app.route('/admin/dashboard')
@login_required
@role_required(['admin'])
def admin_dashboard():
    conn = get_db()
    
    total_users = conn.execute('SELECT COUNT(*) as count FROM users WHERE is_active = 1').fetchone()['count']
    total_blocked = conn.execute('SELECT COUNT(*) as count FROM users WHERE is_active = 0').fetchone()['count']
    
    users_by_role = conn.execute('''
        SELECT role, COUNT(*) as count 
        FROM users 
        WHERE is_active = 1
        GROUP BY role
    ''').fetchall()
    
    conn.close()
    
    stats = {
        'total_users': total_users,
        'total_blocked': total_blocked,
        'users_by_role': users_by_role
    }
    
    return render_template('admin_dashboard.html', stats=stats)

@app.route('/users')
@login_required
@role_required(['admin'])
def users():
    conn = get_db()
    users = conn.execute(
        'SELECT * FROM users WHERE is_active = 1 ORDER BY created_at DESC'
    ).fetchall()
    conn.close()
    
    return render_template('users.html', users=users)

@app.route('/users/blocked')
@login_required
@role_required(['admin'])
def blocked_users():
    conn = get_db()
    users = conn.execute(
        'SELECT * FROM users WHERE is_active = 0 ORDER BY created_at DESC'
    ).fetchall()
    conn.close()
    
    return render_template('blocked_users.html', users=users)

@app.route('/users/add', methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        
        hashed_password = generate_password_hash(password)
        
        try:
            conn = get_db()
            conn.execute(
                'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                (username, hashed_password, role)
            )
            conn.commit()
            conn.close()
            flash('User added successfully!')
            return redirect(url_for('users'))
        except sqlite3.IntegrityError:
            flash('Username already exists')
    
    return render_template('add_user.html')

@app.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
def edit_user(user_id):
    conn = get_db()
    
    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']
        password = request.form.get('password')
        
        if password:
            hashed_password = generate_password_hash(password)
            conn.execute(
                'UPDATE users SET username = ?, role = ?, password = ? WHERE id = ?',
                (username, role, hashed_password, user_id)
            )
        else:
            conn.execute(
                'UPDATE users SET username = ?, role = ? WHERE id = ?',
                (username, role, user_id)
            )
        
        conn.commit()
        conn.close()
        flash('User updated successfully!')
        return redirect(url_for('users'))
    
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    
    if not user:
        flash('User not found')
        return redirect(url_for('users'))
    
    return render_template('edit_user.html', user=user)

@app.route('/users/block/<int:user_id>')
@login_required
@role_required(['admin'])
def block_user(user_id):
    if user_id == session['user_id']:
        flash('You cannot block yourself!')
        return redirect(url_for('users'))
    
    conn = get_db()
    conn.execute('UPDATE users SET is_active = 0 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    flash('User blocked successfully!')
    return redirect(url_for('users'))

@app.route('/users/unblock/<int:user_id>')
@login_required
@role_required(['admin'])
def unblock_user(user_id):
    conn = get_db()
    conn.execute('UPDATE users SET is_active = 1 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    flash('User unblocked successfully!')
    return redirect(url_for('blocked_users'))

if __name__ == '__main__':
    # Create database directory if it doesn't exist
    os.makedirs('database', exist_ok=True)
    init_db()
    app.run(debug=True)
