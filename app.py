import os
import sqlite3
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'Dimitris_secret_key' 

DATABASE_PATH = 'database/crm.db'

def get_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row 
    return conn

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You need to login to view this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'user_id' in session:
        role = session.get('role')
        if role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif role == 'manager':
            return redirect(url_for('manager_dashboard'))
        else:
            return redirect(url_for('employee_dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_in = request.form['username']
        pw_in = request.form['password']
        
        db = get_db()
        # Active users only
        user = db.execute("SELECT * FROM users WHERE username = ? AND is_active = 1", (user_in,)).fetchone()
        db.close()
        
        if user and check_password_hash(user['password'], pw_in):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['is_active'] = user['is_active'] 
            flash('Welcome back!', 'success')
            return redirect(url_for('index'))
        
        flash('Invalid username or password', 'error')
    
    return render_template('login_form.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        uname = request.form['username']
        pw1 = request.form['password']
        pw2 = request.form['password2']
        
        if pw1 != pw2:
            flash('Passwords do not match.')
            return render_template('register_form.html', username=uname)
        
        hashed = generate_password_hash(pw1)
        
        try:
            db = get_db()
            db.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                        (uname, hashed, 'employee'))
            db.commit()
            db.close()
            flash('Account created successfully! Please login.')
            return redirect(url_for('login'))
            
        except sqlite3.IntegrityError:
            flash('Username is already taken. Please choose another.')
            return render_template('register_form.html', username=uname)
    
    return render_template('register_form.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/employee/dashboard')
@login_required
def employee_dashboard():
    db = get_db()
    uid = session['user_id']
    
    total = db.execute('SELECT COUNT(*) as c FROM customers WHERE employee_id = ? AND is_active = 1', (uid,)).fetchone()['c']
    
    # Date filters
    today = db.execute("SELECT COUNT(*) as c FROM contacts WHERE employee_id = ? AND date(contact_date) = date('now')", (uid,)).fetchone()['c']
    week = db.execute("SELECT COUNT(*) as c FROM contacts WHERE employee_id = ? AND date(contact_date) >= date('now', '-6 days')", (uid,)).fetchone()['c']
    month = db.execute("SELECT COUNT(*) as c FROM contacts WHERE employee_id = ? AND date(contact_date) >= date('now', 'start of month')", (uid,)).fetchone()['c']
    
    db.close()
    
    stats = {
        'total_customers': total,
        'contacts_today': today,
        'contacts_week': week,
        'contacts_month': month
    }
    return render_template('employee_dashboard.html', stats=stats)

@app.route('/manage/create')
@login_required
def render_create_page():
    return render_template('create_customer.html')

@app.route('/manage/update')
@login_required
def render_update_page():
    return render_template('update_customer.html')

@app.route('/manage/delete')
@login_required
def render_delete_page():
    db = get_db()
    
    if session['role'] == 'manager':
        customers = db.execute('SELECT * FROM customers WHERE is_active = 1').fetchall()
    else:
        customers = db.execute('SELECT * FROM customers WHERE employee_id = ? AND is_active = 1', 
                                (session['user_id'],)).fetchall()
    db.close()
    return render_template('delete_customer.html', customers=customers)

@app.route('/manage/delete/process', methods=['POST'])
@login_required
def process_delete():
    ids = request.form.getlist('customer_ids')
    
    if ids:
        db = get_db()
        for cid in ids:
            if session['role'] == 'manager':
                db.execute('UPDATE customers SET is_active = 0 WHERE id = ?', (cid,))
            else:
                db.execute('UPDATE customers SET is_active = 0 WHERE id = ? AND employee_id = ?', 
                           (cid, session['user_id']))
        db.commit()
        db.close()
        flash(f'{len(ids)} customer(s) moved to trash.')
        
    return redirect(url_for('render_delete_page'))

@app.route('/add_contact_menu', methods=['GET', 'POST'])
@login_required
def add_contact_menu():
    db = get_db()
    if request.method == 'POST':
        cust_id = request.form['customer_id']
        notes = request.form['notes']
        date = request.form['contact_date']
        
        db.execute('INSERT INTO contacts (customer_id, employee_id, notes, contact_date) VALUES (?, ?, ?, ?)',
                    (cust_id, session['user_id'], notes, date))
        db.commit()
        db.close()
        return redirect(url_for('customers'))
    
    my_customers = db.execute('SELECT * FROM customers WHERE employee_id = ? AND is_active = 1', 
                            (session['user_id'],)).fetchall()
    db.close()
    return render_template('add_contact.html', customers=my_customers, customer=None)

@app.route('/customers')
@login_required
def customers():
    db = get_db()
    role = session['role']
    
    if role == 'manager':
        sql = '''SELECT c.*, u.username as employee_name 
                 FROM customers c 
                 LEFT JOIN users u ON c.employee_id = u.id
                 WHERE c.is_active = 1
                 ORDER BY c.created_at DESC'''
        data = db.execute(sql).fetchall()
    else:
        sql = "SELECT * FROM customers WHERE employee_id = ? AND is_active = 1 ORDER BY created_at DESC"
        data = db.execute(sql, (session['user_id'],)).fetchall()
        
    db.close()
    return render_template('customers.html', customers=data)

@app.route('/search')
@login_required
def search():
    q = request.args.get('q', '')
    
    if not q:
        if session['role'] == 'admin':
            return redirect(url_for('admin_dashboard')) 
        return redirect(url_for('customers'))
    
    db = get_db()
    wildcard = f"%{q}%"
    
    if session['role'] == 'admin':
        sql = "SELECT * FROM users WHERE username LIKE ? OR role LIKE ?"
        res = db.execute(sql, (wildcard, wildcard)).fetchall()
        db.close()
        return render_template('admin_dashboard.html', users=res) 
        
    elif session['role'] == 'manager':
        sql = '''SELECT c.*, u.username as employee_name 
                 FROM customers c 
                 LEFT JOIN users u ON c.employee_id = u.id
                 WHERE c.is_active = 1 
                 AND (c.name LIKE ? OR c.company LIKE ? OR c.email LIKE ?)
                 ORDER BY c.created_at DESC'''
        res = db.execute(sql, (wildcard, wildcard, wildcard)).fetchall()
        db.close()
        return render_template('customers.html', customers=res, search_query=q)
        
    else:
        sql = '''SELECT * FROM customers 
                 WHERE employee_id = ? 
                 AND is_active = 1 
                 AND (name LIKE ? OR company LIKE ? OR email LIKE ?)
                 ORDER BY created_at DESC'''
        res = db.execute(sql, (session['user_id'], wildcard, wildcard, wildcard)).fetchall()
        db.close()
        return render_template('customers.html', customers=res, search_query=q)

@app.route('/customers/add', methods=['GET', 'POST'])
@login_required
def add_customer():
    if request.method == 'POST':
        f = request.form
        db = get_db()
        db.execute('''INSERT INTO customers (name, email, phone, company, category, employee_id)
                      VALUES (?, ?, ?, ?, ?, ?)''', 
                      (f['name'], f.get('email'), f.get('phone'), 
                       f.get('company'), f.get('category'), session['user_id']))
        db.commit()
        db.close()
        return redirect(url_for('customers'))
        
    return render_template('create_customer.html') 

@app.route('/customers/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_customer(id):
    db = get_db()
    is_manager = (session['role'] == 'manager')
    
    if request.method == 'POST':
        f = request.form
        if is_manager:
             sql = "UPDATE customers SET name=?, email=?, phone=?, company=?, category=? WHERE id=?"
             params = (f['name'], f['email'], f['phone'], f['company'], f['category'], id)
        else:
             sql = "UPDATE customers SET name=?, email=?, phone=?, company=?, category=? WHERE id=? AND employee_id=?"
             params = (f['name'], f['email'], f['phone'], f['company'], f['category'], id, session['user_id'])
             
        db.execute(sql, params)
        db.commit()
        db.close()
        return redirect(url_for('customers'))
    
    if is_manager:
        customer = db.execute('SELECT * FROM customers WHERE id = ?', (id,)).fetchone()
    else:
        customer = db.execute('SELECT * FROM customers WHERE id = ? AND employee_id = ?', 
                               (id, session['user_id'])).fetchone()
    db.close()
    
    if not customer:
        flash('Customer not found or access denied')
        return redirect(url_for('customers'))
        
    return render_template('edit_customer.html', customer=customer)

@app.route('/customers/delete/<int:id>')
@login_required
def delete_customer(id):
    db = get_db()
    if session['role'] == 'manager':
        db.execute('UPDATE customers SET is_active = 0 WHERE id = ?', (id,))
    else:
        db.execute('UPDATE customers SET is_active = 0 WHERE id = ? AND employee_id = ?', 
                   (id, session['user_id']))
    db.commit()
    db.close()
    return redirect(url_for('customers'))

@app.route('/customers/<int:id>/contacts')
@login_required
def customer_contacts(id):
    db = get_db()
    
    if session['role'] == 'manager':
        cust = db.execute('SELECT * FROM customers WHERE id = ?', (id,)).fetchone()
    else:
        cust = db.execute('SELECT * FROM customers WHERE id = ? AND employee_id = ?', 
                           (id, session['user_id'])).fetchone()
                           
    if not cust:
        db.close()
        return redirect(url_for('customers'))
        
    sql = '''SELECT c.*, u.username as employee_name
             FROM contacts c
             JOIN users u ON c.employee_id = u.id
             WHERE c.customer_id = ?
             ORDER BY c.contact_date DESC'''
    history = db.execute(sql, (id,)).fetchall()
    db.close()
    
    return render_template('customer_contacts.html', customer=cust, contacts=history)

@app.route('/customers/<int:id>/add_contact', methods=['GET', 'POST'])
@login_required
def add_contact(id):
    db = get_db()
    if request.method == 'POST':
        notes = request.form['notes']
        no_resp = 1 if request.form.get('no_response') else 0
        
        db.execute('INSERT INTO contacts (customer_id, employee_id, notes, no_response) VALUES (?, ?, ?, ?)',
                    (id, session['user_id'], notes, no_resp))
        db.commit()
        db.close()
        return redirect(url_for('customer_contacts', id=id))
    
    cust = db.execute('SELECT * FROM customers WHERE id = ?', (id,)).fetchone()
    db.close()
    return render_template('add_contact.html', customer=cust)

@app.route('/manager/dashboard')
@login_required
def manager_dashboard():
    if session['role'] != 'manager':
        flash("Access Denied")
        return redirect(url_for('index'))
    return render_template('manager_dashboard.html')

@app.route('/manager/view_employees')
@login_required
def view_employees():
    if session['role'] != 'manager':
        return redirect(url_for('index'))
        
    db = get_db()
    
    # 1. Total employees
    count = db.execute("SELECT COUNT(*) FROM users WHERE role = 'employee'").fetchone()[0]
    
    # 2. Activity stats
    sql = """
        SELECT 
            u.username,
            (SELECT COUNT(*) FROM customers c WHERE c.employee_id = u.id AND c.is_active = 1) as total_customers,
            (SELECT COUNT(*) FROM contacts ct WHERE ct.employee_id = u.id) as total_contacts
        FROM users u
        WHERE u.role = 'employee'
    """
    rows = db.execute(sql).fetchall()
    db.close()
    
    emp_list = [dict(row) for row in rows]
    return render_template('view_employees.html', employees=emp_list, stats={'total_employees': count})

@app.route('/manager/inactive_customers')
@login_required
def inactive_customers():
    if session['role'] != 'manager':
        return redirect(url_for('index'))
        
    days = request.args.get('days', '30')
    
    db = get_db()
    sql = '''
        SELECT c.*, u.username as employee_name, MAX(ct.contact_date) as last_contact
        FROM customers c
        LEFT JOIN contacts ct ON c.id = ct.customer_id
        JOIN users u ON c.employee_id = u.id
        WHERE c.is_active = 1
        GROUP BY c.id
        HAVING last_contact IS NULL OR date(last_contact) < date('now', '-' || ? || ' days')
    '''
    data = db.execute(sql, (days,)).fetchall()
    db.close()
    
    return render_template('inactive_customers.html', customers=data, days=days)

@app.route('/manager/no_response_customers')
@login_required
def no_response_customers():
    if session['role'] != 'manager':
        return redirect(url_for('index'))
        
    db = get_db()
    sql = """
        SELECT 
            customers.name as customer_name,
            customers.company,
            customers.phone,
            users.username as employee_name,
            contacts.contact_date,
            contacts.notes
        FROM contacts
        JOIN customers ON contacts.customer_id = customers.id
        JOIN users ON contacts.employee_id = users.id
        WHERE contacts.no_response = 1
        ORDER BY contacts.contact_date DESC
    """
    data = db.execute(sql).fetchall()
    db.close()
    return render_template('no_response_customers.html', reports=data)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if session['role'] != 'admin':
        return redirect(url_for('index'))
    
    db = get_db()
    users = db.execute('SELECT * FROM users').fetchall()
    db.close()
    return render_template('admin_dashboard.html', users=users)

@app.route('/users')
@login_required
def view_users():
    if session['role'] != 'admin':
        return redirect(url_for('index'))
    
    db = get_db()
    users = db.execute('SELECT * FROM users').fetchall()
    db.close()
    return render_template('admin_dashboard.html', users=users) 

@app.route('/users/create', methods=['GET', 'POST'])
@login_required
def create_user(): 
    if session['role'] != 'admin':
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        f = request.form
        uname = f['username']
        
        hashed = generate_password_hash(f['password'])
        
        try:
            db = get_db()
            db.execute('INSERT INTO users (username, password, role, phone, email, created_at) VALUES (?, ?, ?, ?, ?, ?)', 
                        (uname, hashed, f['role'], f.get('phone', ''), f.get('email', ''), 
                         f.get('created_at', datetime.now().strftime('%Y-%m-%d'))))
            db.commit()
            db.close()
            flash(f'User {uname} created.')
            return redirect(url_for('view_users'))
        except Exception as e:
            print(f"Error creating user: {e}")
            flash('Error: Username likely taken.')
            
    return render_template('create_user.html')

@app.route('/users/update_menu')
@login_required
def render_update_user():
    if session['role'] != 'admin':
        return redirect(url_for('index'))
    
    db = get_db()
    users = db.execute('SELECT * FROM users').fetchall()
    db.close()
    return render_template('update_user.html', users=users)

@app.route('/users/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_user(id):
    if session['role'] != 'admin':
        return redirect(url_for('index'))
        
    db = get_db()
    if request.method == 'POST':
        f = request.form
        try:
            db.execute('UPDATE users SET username=?, phone=?, email=?, role=?, created_at=? WHERE id=?',
                        (f['username'], f.get('phone', ''), f.get('email', ''), f['role'], f.get('created_at', ''), id))
            db.commit()
            flash('User updated successfully')
            db.close()
            return redirect(url_for('view_users'))
        except Exception as e:
            print(e)
            flash('Update failed.')
            
    user = db.execute('SELECT * FROM users WHERE id = ?', (id,)).fetchone()
    db.close()
    return render_template('edit_user.html', user=user)

@app.route('/users/delete_menu')
@login_required
def render_delete_user():
    if session['role'] != 'admin':
        return redirect(url_for('index'))
    
    db = get_db()
    users = db.execute('SELECT * FROM users').fetchall()
    db.close()
    return render_template('delete_user.html', users=users)

@app.route('/users/delete/process', methods=['POST'])
@login_required
def process_delete_user():
    if session['role'] != 'admin':
        return redirect(url_for('index'))
    
    ids = request.form.getlist('user_ids')
    
    if ids:
        db = get_db()
        count = 0
        for uid in ids:
            if int(uid) == session['user_id']:
                flash("You cannot delete your own account while logged in.")
                continue
            
            db.execute('DELETE FROM users WHERE id = ?', (uid,))
            count += 1
            
        db.commit()
        db.close()
        flash(f'{count} user(s) permanently deleted.')
        
    return redirect(url_for('render_delete_user'))

def init_db():
    if not os.path.exists('database'):
        os.makedirs('database')
        
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        phone TEXT,
        email TEXT,
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT,
        phone TEXT,
        company TEXT,
        category TEXT DEFAULT 'Lead',
        is_active INTEGER DEFAULT 1,
        employee_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (employee_id) REFERENCES users(id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS contacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER,
        employee_id INTEGER,
        contact_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        notes TEXT,
        no_response INTEGER DEFAULT 0,
        FOREIGN KEY (customer_id) REFERENCES customers(id),
        FOREIGN KEY (employee_id) REFERENCES users(id)
    )''')
    
    # Seed data if empty
    if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        print("Seeding database...")
        
        users = [
            ('Lizzie Stark', 'admin123', 'admin', 'lizziestrk@outlook.com', 1),
            ('Lip Gallagher', 'manager123', 'manager', 'lipgallagher@gmail.com', 0),
            ('Paul Kellerman', 'employee123', 'employee', 'pkellerman@gmali.com', 1),
            ('Jordan Carter', '123456', 'employee', 'jcarter@gmail.com', 0)
        ]
        
        for u in users:
            pw_hash = generate_password_hash(u[1])
            c.execute("INSERT INTO users (username, password, role, email, is_active) VALUES (?, ?, ?, ?, ?)", 
                     (u[0], pw_hash, u[2], u[3], u[4]))
        
        print("Seeding complete.")
        
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db() 
    app.run(debug=True)