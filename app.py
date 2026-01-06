from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'Dimitris' # Random key for security

DB_NAME = 'database/crm.db'

def connect_db():
    con = sqlite3.connect(DB_NAME)
    con.row_factory = sqlite3.Row
    return con

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first')
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
        user_input = request.form['username']
        pass_input = request.form['password']
        
        con = connect_db()
        cur = con.cursor()
        
        sql = "SELECT * FROM users WHERE username = ? AND is_active = 1"
        user = cur.execute(sql, (user_input,)).fetchone()
        con.close()
        
        if user and check_password_hash(user['password'], pass_input):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['is_active'] = user['is_active'] 
            flash('Logged in successfully', 'success')
            return redirect(url_for('index'))
        else:
            flash('Wrong username or password', 'error')
    
    return render_template('login_form.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        pwd1 = request.form['password']
        pwd2 = request.form['password2']
        
        if pwd1 != pwd2:
            flash('Passwords need to match')
            return render_template('register_form.html', username=username)
        
        hashed = generate_password_hash(pwd1)
        
        try:
            con = connect_db()
            con.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                        (username, hashed, 'employee'))
            con.commit()
            con.close()
            flash('Account created! You can login now.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            print(f"Error registering {username}") 
            flash('That username is already taken')
            return render_template('register_form.html', username=username)
    
    return render_template('register_form.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out')
    return redirect(url_for('index'))

# --- EMPLOYEE ROUTES ---

@app.route('/employee/dashboard')
@login_required
def employee_dashboard():
    con = connect_db()
    uid = session['user_id']
    
    total = con.execute('SELECT COUNT(*) as c FROM customers WHERE employee_id = ? AND is_active = 1', (uid,)).fetchone()['c']
    
    today_sql = "SELECT COUNT(*) as c FROM contacts WHERE employee_id = ? AND date(contact_date) = date('now')"
    contacts_today = con.execute(today_sql, (uid,)).fetchone()['c']
    
    week_sql = "SELECT COUNT(*) as c FROM contacts WHERE employee_id = ? AND date(contact_date) >= date('now', '-6 days')"
    contacts_week = con.execute(week_sql, (uid,)).fetchone()['c']
    
    month_sql = "SELECT COUNT(*) as c FROM contacts WHERE employee_id = ? AND date(contact_date) >= date('now', 'start of month')"
    contacts_month = con.execute(month_sql, (uid,)).fetchone()['c']
    
    con.close()
    
    stats_data = {
        'total_customers': total,
        'contacts_today': contacts_today,
        'contacts_week': contacts_week,
        'contacts_month': contacts_month
    }
    
    return render_template('employee_dashboard.html', stats=stats_data)

# --- MANAGE CUSTOMERS ROUTES ---

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
    con = connect_db()
    if session['role'] == 'manager':
        customers = con.execute('SELECT * FROM customers WHERE is_active = 1').fetchall()
    else:
        customers = con.execute('SELECT * FROM customers WHERE employee_id = ? AND is_active = 1', 
                                (session['user_id'],)).fetchall()
    con.close()
    return render_template('delete_customer.html', customers=customers)

@app.route('/manage/delete/process', methods=['POST'])
@login_required
def process_delete():
    customer_ids = request.form.getlist('customer_ids')
    if customer_ids:
        con = connect_db()
        for cid in customer_ids:
            if session['role'] == 'manager':
                con.execute('UPDATE customers SET is_active = 0 WHERE id = ?', (cid,))
            else:
                con.execute('UPDATE customers SET is_active = 0 WHERE id = ? AND employee_id = ?', 
                            (cid, session['user_id']))
        con.commit()
        con.close()
        flash(f'{len(customer_ids)} customer(s) deleted.')
    return redirect(url_for('render_delete_page'))

@app.route('/add_contact_menu', methods=['GET', 'POST'])
@login_required
def add_contact_menu():
    con = connect_db()
    if request.method == 'POST':
        customer_id = request.form['customer_id']
        notes = request.form['notes']
        contact_date = request.form['contact_date']
        con.execute('INSERT INTO contacts (customer_id, employee_id, notes, contact_date) VALUES (?, ?, ?, ?)',
                    (customer_id, session['user_id'], notes, contact_date))
        con.commit()
        con.close()
        return redirect(url_for('customers'))
    customers = con.execute('SELECT * FROM customers WHERE employee_id = ? AND is_active = 1', 
                            (session['user_id'],)).fetchall()
    con.close()
    return render_template('add_contact.html', customers=customers, customer=None)

# ----------------------------------------------------

@app.route('/customers')
@login_required
def customers():
    con = connect_db()
    role = session['role']
    if role == 'manager':
        sql = '''SELECT c.*, u.username as employee_name 
                 FROM customers c 
                 LEFT JOIN users u ON c.employee_id = u.id
                 WHERE c.is_active = 1
                 ORDER BY c.created_at DESC'''
        data = con.execute(sql).fetchall()
    else:
        sql = "SELECT * FROM customers WHERE employee_id = ? AND is_active = 1 ORDER BY created_at DESC"
        data = con.execute(sql, (session['user_id'],)).fetchall()
    con.close()
    return render_template('customers.html', customers=data)

# --- SEARCH ROUTE ---
@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '')
    con = connect_db()
    if not query:
        con.close()
        if session['role'] == 'admin':
            return redirect(url_for('admin_dashboard')) 
        else:
            return redirect(url_for('customers'))
    
    search_term = f"%{query}%"
    
    if session['role'] == 'admin':
        sql = "SELECT * FROM users WHERE username LIKE ? OR role LIKE ?"
        results = con.execute(sql, (search_term, search_term)).fetchall()
        con.close()
        return render_template('admin_dashboard.html', users=results) 
        
    elif session['role'] == 'manager':
        sql = '''SELECT c.*, u.username as employee_name 
                 FROM customers c 
                 LEFT JOIN users u ON c.employee_id = u.id
                 WHERE c.is_active = 1 
                 AND (c.name LIKE ? OR c.company LIKE ? OR c.email LIKE ?)
                 ORDER BY c.created_at DESC'''
        params = (search_term, search_term, search_term)
        results = con.execute(sql, params).fetchall()
        con.close()
        return render_template('customers.html', customers=results, search_query=query)
    else:
        sql = '''SELECT * FROM customers 
                 WHERE employee_id = ? 
                 AND is_active = 1 
                 AND (name LIKE ? OR company LIKE ? OR email LIKE ?)
                 ORDER BY created_at DESC'''
        params = (session['user_id'], search_term, search_term, search_term)
        results = con.execute(sql, params).fetchall()
        con.close()
        return render_template('customers.html', customers=results, search_query=query)

@app.route('/customers/add', methods=['GET', 'POST'])
@login_required
def add_customer():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form.get('email')
        phone = request.form.get('phone')
        company = request.form.get('company')
        cat = request.form.get('category')
        profession = request.form.get('profession', '')
        revenue = request.form.get('revenue', '')
        address = request.form.get('address', '')
        created_at = request.form.get('created_at')
        
        con = connect_db()
        con.execute('''INSERT INTO customers (name, email, phone, company, category, employee_id)
                       VALUES (?, ?, ?, ?, ?, ?)''', 
                       (name, email, phone, company, cat, session['user_id']))
        con.commit()
        con.close()
        return redirect(url_for('customers'))
    return render_template('create_customer.html') 

@app.route('/customers/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_customer(id):
    con = connect_db()
    is_manager = (session['role'] == 'manager')
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        comp = request.form['company']
        cat = request.form['category']
        if is_manager:
             sql = "UPDATE customers SET name=?, email=?, phone=?, company=?, category=? WHERE id=?"
             params = (name, email, phone, comp, cat, id)
        else:
             sql = "UPDATE customers SET name=?, email=?, phone=?, company=?, category=? WHERE id=? AND employee_id=?"
             params = (name, email, phone, comp, cat, id, session['user_id'])
        con.execute(sql, params)
        con.commit()
        con.close()
        return redirect(url_for('customers'))
    if is_manager:
        customer = con.execute('SELECT * FROM customers WHERE id = ?', (id,)).fetchone()
    else:
        customer = con.execute('SELECT * FROM customers WHERE id = ? AND employee_id = ?', 
                               (id, session['user_id'])).fetchone()
    con.close()
    if not customer:
        flash('Customer not found or access denied')
        return redirect(url_for('customers'))
    return render_template('edit_customer.html', customer=customer)

@app.route('/customers/delete/<int:id>')
@login_required
def delete_customer(id):
    con = connect_db()
    if session['role'] == 'manager':
        con.execute('UPDATE customers SET is_active = 0 WHERE id = ?', (id,))
    else:
        con.execute('UPDATE customers SET is_active = 0 WHERE id = ? AND employee_id = ?', 
                    (id, session['user_id']))
    con.commit()
    con.close()
    return redirect(url_for('customers'))

@app.route('/customers/<int:id>/contacts')
@login_required
def customer_contacts(id):
    con = connect_db()
    if session['role'] == 'manager':
        cust = con.execute('SELECT * FROM customers WHERE id = ?', (id,)).fetchone()
    else:
        cust = con.execute('SELECT * FROM customers WHERE id = ? AND employee_id = ?', 
                           (id, session['user_id'])).fetchone()
    if not cust:
        con.close()
        return redirect(url_for('customers'))
    sql = '''SELECT c.*, u.username as employee_name
             FROM contacts c
             JOIN users u ON c.employee_id = u.id
             WHERE c.customer_id = ?
             ORDER BY c.contact_date DESC'''
    contacts = con.execute(sql, (id,)).fetchall()
    con.close()
    return render_template('customer_contacts.html', customer=cust, contacts=contacts)

@app.route('/customers/<int:id>/add_contact', methods=['GET', 'POST'])
@login_required
def add_contact(id):
    if request.method == 'POST':
        notes = request.form['notes']
        no_resp = 1 if request.form.get('no_response') else 0
        con = connect_db()
        con.execute('INSERT INTO contacts (customer_id, employee_id, notes, no_response) VALUES (?, ?, ?, ?)',
                    (id, session['user_id'], notes, no_resp))
        con.commit()
        con.close()
        return redirect(url_for('customer_contacts', id=id))
    con = connect_db()
    cust = con.execute('SELECT * FROM customers WHERE id = ?', (id,)).fetchone()
    con.close()
    return render_template('add_contact.html', customer=cust)

# --- MANAGER ROUTES ---

@app.route('/manager/dashboard')
@login_required
def manager_dashboard():
    if session['role'] != 'manager':
        return redirect(url_for('index'))
    return render_template('manager_dashboard.html')

@app.route('/manager/view_employees')
@login_required
def view_employees():
    if session['role'] != 'manager':
        return redirect(url_for('index'))
        
    con = connect_db()
    
    total_emp = con.execute("SELECT COUNT(*) FROM users WHERE role = 'employee'").fetchone()[0]
    
    query = """
        SELECT 
            u.username,
            (SELECT COUNT(*) FROM customers c WHERE c.employee_id = u.id AND c.is_active = 1) as total_customers,
            (SELECT COUNT(*) FROM contacts ct WHERE ct.employee_id = u.id) as total_contacts
        FROM users u
        WHERE u.role = 'employee'
    """
    rows = con.execute(query).fetchall()
    con.close()
    
    employees = [dict(row) for row in rows]
    
    return render_template('view_employees.html', employees=employees, stats={'total_employees': total_emp})

@app.route('/manager/inactive_customers')
@login_required
def inactive_customers():
    if session['role'] != 'manager':
        return redirect(url_for('index'))
        
    days = request.args.get('days', '30')
    con = connect_db()
    sql = '''
        SELECT c.*, u.username as employee_name, MAX(ct.contact_date) as last_contact
        FROM customers c
        LEFT JOIN contacts ct ON c.id = ct.customer_id
        JOIN users u ON c.employee_id = u.id
        WHERE c.is_active = 1
        GROUP BY c.id
        HAVING last_contact IS NULL OR date(last_contact) < date('now', '-' || ? || ' days')
    '''
    data = con.execute(sql, (days,)).fetchall()
    con.close()
    return render_template('inactive_customers.html', customers=data, days=days)

@app.route('/manager/no_response_customers')
@login_required
def no_response_customers():
    if session['role'] != 'manager':
        return redirect(url_for('index'))
        
    con = connect_db()
    query = """
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
    reports = con.execute(query).fetchall()
    con.close()
    return render_template('no_response_customers.html', reports=reports)


# --- ADMIN ROUTES ---

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if session['role'] != 'admin':
        return redirect(url_for('index'))
    
    con = connect_db()
    users = con.execute('SELECT * FROM users').fetchall()
    con.close()
    
    return render_template('admin_dashboard.html', users=users)

@app.route('/users')
@login_required
def view_users():
    if session['role'] != 'admin':
        return redirect(url_for('index'))
    con = connect_db()
    all_users = con.execute('SELECT * FROM users').fetchall()
    con.close()
    return render_template('admin_dashboard.html', users=all_users) 

@app.route('/users/create', methods=['GET', 'POST'])
@login_required
def create_user(): 
    if session['role'] != 'admin':
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        uname = request.form['username']
        pw = request.form['password']
        role = request.form['role']
        phone = request.form.get('phone', '')
        email = request.form.get('email', '')
        created = request.form.get('created_at', datetime.now().strftime('%Y-%m-%d'))
        
        hashed = generate_password_hash(pw)
        try:
            con = connect_db()
            con.execute('INSERT INTO users (username, password, role, phone, email, created_at) VALUES (?, ?, ?, ?, ?, ?)', 
                        (uname, hashed, role, phone, email, created))
            con.commit()
            con.close()
            flash('User created')
            return redirect(url_for('view_users'))
        except Exception as e:
            print(e)
            flash('Username taken or error occurred')
            
    return render_template('create_user.html')

# -- UPDATE USERS --

@app.route('/users/update_menu')
@login_required
def render_update_user():
    if session['role'] != 'admin':
        return redirect(url_for('index'))
    con = connect_db()
    users = con.execute('SELECT * FROM users').fetchall()
    con.close()
    return render_template('update_user.html', users=users)

@app.route('/users/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_user(id):
    if session['role'] != 'admin':
        return redirect(url_for('index'))
        
    con = connect_db()
    
    if request.method == 'POST':
        uname = request.form['username']
        phone = request.form.get('phone', '')
        email = request.form.get('email', '')
        role = request.form['role']
        created = request.form.get('created_at', '')
        
        try:
            con.execute('UPDATE users SET username=?, phone=?, email=?, role=?, created_at=? WHERE id=?',
                        (uname, phone, email, role, created, id))
            con.commit()
            flash('User updated successfully')
            con.close()
            return redirect(url_for('view_users'))
        except Exception as e:
            print(e)
            flash('Error updating user')
            
    user = con.execute('SELECT * FROM users WHERE id = ?', (id,)).fetchone()
    con.close()
    return render_template('edit_user.html', user=user)

# -- DELETE USERS --

@app.route('/users/delete_menu')
@login_required
def render_delete_user():
    if session['role'] != 'admin':
        return redirect(url_for('index'))
    con = connect_db()
    users = con.execute('SELECT * FROM users').fetchall()
    con.close()
    return render_template('delete_user.html', users=users)

@app.route('/users/delete/process', methods=['POST'])
@login_required
def process_delete_user():
    if session['role'] != 'admin':
        return redirect(url_for('index'))
    
    user_ids = request.form.getlist('user_ids')
    if user_ids:
        con = connect_db()
        for uid in user_ids:
            if int(uid) == session['user_id']:
                flash("Cannot delete yourself.")
                continue
            con.execute('DELETE FROM users WHERE id = ?', (uid,))
        con.commit()
        con.close()
        flash(f'{len(user_ids)} user(s) deleted.')
    return redirect(url_for('render_delete_user'))


# --- DATABASE SETUP ---

if __name__ == '__main__':
    if not os.path.exists('database'):
        os.makedirs('database')
    conn = sqlite3.connect(DB_NAME)
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
    
    user_count = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if user_count == 0:
        pw = generate_password_hash('admin123')
        c.execute("INSERT INTO users (username, password, role, email, is_active) VALUES (?, ?, ?, ?, ?)", 
                 ('Lizzie Stark', pw, 'admin', 'lizziestrk@outlook.com', 1))

        pw = generate_password_hash('manager123')
        c.execute("INSERT INTO users (username, password, role, email, is_active) VALUES (?, ?, ?, ?, ?)", 
                 ('Lip Gallagher', pw, 'manager', 'lipgallagher@gmail.com', 0))

        pw = generate_password_hash('employee123')
        c.execute("INSERT INTO users (username, password, role, email, is_active) VALUES (?, ?, ?, ?, ?)", 
                 ('Paul Kellerman', pw, 'employee', 'pkellerman@gmali.com', 1))

        pw = generate_password_hash('123456') 
        c.execute("INSERT INTO users (username, password, role, email, is_active) VALUES (?, ?, ?, ?, ?)", 
                 ('Jordan Carter', pw, 'employee', 'jcarter@gmail.com', 0))
        
    conn.commit()
    conn.close()
    app.run(debug=True)
