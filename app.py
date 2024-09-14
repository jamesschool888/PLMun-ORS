from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from datetime import datetime
from flask_mail import Mail, Message
import secrets
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
import hashlib

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Generates hashes
bcrypt = Bcrypt(app)
# Keys for Encryption
encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)
def encrypt_data(data):
    return cipher_suite.encrypt(data.encode())
def decrypt_data(encrypted_data):
    return cipher_suite.decrypt(encrypted_data).decode()

hashed_user1 = hashlib.sha256('user1'.encode()).hexdigest()
hashed_admin1 = hashlib.sha256('admin1'.encode()).hexdigest()
hashed_admin2 = hashlib.sha256('admin2'.encode()).hexdigest()

hashed_password_user1 = bcrypt.generate_password_hash('userpass').decode('utf-8')
hashed_password_admin1 = bcrypt.generate_password_hash('adminpass1').decode('utf-8')
hashed_password_admin2 = bcrypt.generate_password_hash('adminpass2').decode('utf-8')

print(f'user1 password: {hashed_password_user1}' + f' hashed username: {hashed_user1}')
print(f'admin1 password: {hashed_password_admin1}' + f' hashed username: {hashed_admin1}')
print(f'admin2 password: {hashed_password_admin2}'+ f' hashed username: {hashed_admin2}')

# Hashes passwords and hashed usernames, very secure.
USER_CREDENTIALS = {
    hashed_user1: hashed_password_user1,
    hashed_admin1: hashed_password_admin1,
    hashed_admin2: hashed_password_admin2
}

requestNum = 0
dateNow = datetime.now()
date = dateNow.strftime("%Y-%m-%d")

table_data = []
ongoing_table_data = []
finished_table_data = []
requests_db = []
notifications_db = []
data = {}

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'orvillejames123@gmail.com'
app.config['MAIL_PASSWORD'] =  'uigs jqbr ayyv vhcl'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

documentPrices = {
    # Certificates
    "Cert. of Grades": 30,
    "Cert. of Enrolment": 30,
    "CAV / S.O Cert": 30,
    "Cert. of Earned Units": 30,

    # Forms
    "Evaluation Form": 30,
    "Subject Credit Form": 30,
    "Shifting Form": 30,
    "Completion Form": 30,
    "AW / Adding /Dropping Form": 30,

    # For CAV Requests
    "CAV": 80,

    # Others
    "COM Reprint": 120,
    "Diploma": 100,
    "Cert. of Candidacy for Graduation": 30,
    "Medium of Instruction": 30,

    # Purpose
    "For DFA": 0,
    "For CHED": 0,
    "For PNP": 0,
    "For Board Exam (PRC)": 0,
    "For Scholarship": 0,
    "Others": 0,
}

@app.route("/", methods=["GET", "POST"])
def index():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        hashed_username = hashlib.sha256(username.encode()).hexdigest()
        
        # Check if the username and password match
        if hashed_username in USER_CREDENTIALS and bcrypt.check_password_hash(USER_CREDENTIALS[hashed_username], password):
            session['username'] = username
            if username.startswith('admin'):
                session['role'] = 'admin'
                return redirect(url_for("pending_page"))
            else:
                session['role'] = 'user'
                return redirect(url_for("home"))
        else:
            error = "Invalid username or password"
    return render_template('index.html', error=error)

@app.route('/home', methods=['POST'])
def submit_form():
    
    global requestNum
    if request.method == 'POST':
        # Get form data
        first_name = encrypt_data(request.form['firstName'])
        last_name = encrypt_data(request.form['lastName'])
        student_number = encrypt_data(request.form['Student Number'])
        email = encrypt_data(request.form['email'])
        selected_documents = request.form.getlist('document')
        selected_purposes = request.form.getlist('purpose')
        other_purpose = request.form['other_purpose']
        requestNum += 1
        formatted_request_num = f"{requestNum:06d}"
        
        total_price = sum(documentPrices[doc] for doc in selected_documents)
        
        print(
            f"\nFirst Name: {(first_name)}\n"
            f"Last Name: {(last_name)}\n"
            f"Student Number: {(student_number)}\n"
            f"Email: {(email)}\n"
            f"Documents Requested: {selected_documents}\n"  # Display selected documents
            f"Purpose: {selected_purposes}\n"
            f"Other purpose: {other_purpose}\n"
            f"Request no: {formatted_request_num}\n"
            f"Total Price: ₱{total_price}\n"
        )
        
        msg = (f'Hello, {decrypt_data(first_name)} {decrypt_data(last_name)}!\n'
        f'The form you sent has been received by our admin.\n'
        f'Here is the summary of your request:\n'
        f'Student Number: {decrypt_data(student_number)}\n'
        f'Email: {decrypt_data(email)}\n'
        f'Document Requested: {selected_documents}\n'
        f'Purpose: {selected_purposes}\n'
        f'Other Purpose: {other_purpose}\n'
        f'Request no: {formatted_request_num}\n'
        f'Price: ₱{total_price}\n'
        f'\nIf you think you made a mistake in filling up the forms, you may click the "Pending Request" in the navigation bar.\n'
        f'A dropdown list of your requests will show up and you may click "Cancel".'
        )
        
        message = Message(sender="orvillejames123@gmail.com", subject=formatted_request_num, recipients=[decrypt_data(email)])
        message.body = msg
        
        mail.send(message)
        
        table_data.append({
            'first_name': (first_name),
            'last_name': (last_name),
            'student_number': (student_number),
            'email': (email),
            'document': selected_documents,  # Store each document separately
            'purpose': selected_purposes,  
            'other_purpose': other_purpose,
            'date': date,
            'requestNum': requestNum,
            'formatted_request_num': formatted_request_num,
            'total_price': total_price,
        })
            
        requests_db.append({
            'first_name': (first_name),
            'last_name': (last_name),
            'student_number': (student_number),
            'email': (email),
            'document': selected_documents,  # Store each document separately
            'purpose': selected_purposes,
            'other_purpose': other_purpose,
            'date': date,
            'requestNum': requestNum,
            'formatted_request_num': formatted_request_num,
            'total_price': total_price,
        })
        return redirect(url_for('home'))
    return "Method not allowed"  # Handle cases when the method is not 'POST;

#client side
@app.route('/cancel_request', methods=['POST'])
def cancel_request():
    request_id = request.form.get('request_id')
    for req in requests_db:
        if req['requestNum'] == int(request_id):
            requests_db.remove(req)
            break
    for data in table_data:
        if data['requestNum'] == int(request_id):
            table_data.remove(data)
            break
    return redirect(url_for('home'))


#admin side
@app.route('/approve_request', methods=['POST'])
def approve_request():
    request_id = request.form.get('request_id')
    claim_date = request.form.get('claim_date')
    if request_id: 
        formatted_request_num = f"{int(request_id):06d}"
        for req in requests_db:
            if req['requestNum'] == int(request_id):
                price = req['total_price']
                selected_documents = req['document']
                document_lines = [f'<br>             {doc}' for doc in selected_documents]
                notifications_db.append({
                'processed': (f'<strong>Request#{formatted_request_num}</strong> has been approved.'
                            f'{"".join(document_lines)}'
                            f'<br>Claim on: {claim_date}' 
                            f'<br>Please prepare the exact amount of: ₱{price}')
                })
                req['claim_date'] = claim_date
                ongoing_table_data.append(req)
                print(ongoing_table_data)
                requests_db.remove(req)
                break
        for data in table_data:
            if data['requestNum'] == int(request_id):
                table_data.remove(data)
                print(table_data)
                break
    return redirect(url_for('pending_page'))

@app.route('/approve_selected', methods=['POST'])
def approve_selected():
    data = request.json
    claim_date = data.get('claim_date')
    selected_ids = data.get('selectedIds', [])
    date_processed = datetime.now().replace(microsecond=0)
    
    print("Selected IDs:", selected_ids)  # Debugging print statement
    
    for req in requests_db[:]:
        print("Current request:", req)  # Debugging print statement
        
        if str(req['requestNum']) in selected_ids:
            formatted_request_num = f"{req['requestNum']:06d}"
            price = req['total_price']
            req['claim_date'] = claim_date
            selected_documents = req['document']
            document_lines = [f'<br>             {doc}' for doc in selected_documents]
            notifications_db.append({
                'processed': (f'<strong>Request#{formatted_request_num}</strong> has been approved.'
                            f'{"".join(document_lines)}'
                            f'<br>Claim on: {claim_date}'
                            f'<br>Please prepare the exact amount of: ₱{price}'),
                'date_processed': f'Date processed: {date_processed}'
            })
            ongoing_table_data.append(req)
            requests_db.remove(req)
            # Remove the approved request from table_data
            for data in table_data[:]:
                if data['requestNum'] == req['requestNum']:
                    table_data.remove(data)
                    break

    return redirect(url_for('pending_page'))

@app.route('/decline_request', methods=['POST'])
def decline_request():
    request_id = request.form.get('request_id') 
    reason_for_decline = request.form.get('reason_for_decline')
    if request_id:
        formatted_request_num = f"{int(request_id):06d}"
        notifications_db.append({
            'processed': f'<strong>Request #{formatted_request_num}</strong> has been declined',
            'reason': reason_for_decline
        })
        request_id = request.form.get('request_id')
        for req in requests_db:
            if req['requestNum'] == int(request_id):
                req['reason_for_decline'] = reason_for_decline
                finished_table_data.append(req)
                requests_db.remove(req)
                print(finished_table_data)
                break
        for data in table_data:
            if data['requestNum'] == int(request_id):
                table_data.remove(data)
                break
    return redirect(url_for('pending_page'))

@app.route('/decline_selected', methods=['POST'])
def decline_selected():
    print("does this /decline_selected line even work")
    data = request.json
    reason_for_decline = data.get('reasonForDecline')
    selected_ids = data.get('selectedIds', [])
    deleted_rows = []
    current_user = session.get('username')
    date_processed = datetime.now().replace(microsecond=0)
    
    for requestNum in selected_ids:
    # Find the row in table_data with the matching requestNum
        for row in table_data.copy():
            if row['requestNum'] == requestNum:
            # Update the row with decline information
                row['reason_for_decline'] = reason_for_decline
                row['admin_username'] = current_user
                row['date_processed'] = date_processed
                finished_table_data.append(row)
                table_data.remove(row)
                deleted_rows.append(row)

    # Remove rows from requests_db based on selected_ids
    for row in requests_db.copy():
        if row['requestNum'] == requestNum:
            requests_db.remove(row)
    
    # Format the requestNum for notification
    formatted_request_num = f"#{requestNum:06d}"
    notifications_db.append({
        'processed': f'<strong>Declined Request for: {formatted_request_num}</strong>',
        'reason': reason_for_decline,
        'date_processed': f'Date processed: {date_processed}',
        'admin_username': f'Processed by: {current_user}'
    })
    return redirect(url_for('pending_page'))

@app.route('/home', methods=["GET", "POST"])
def home():
    if 'username' not in session or session.get('role') != 'user':
        return redirect(url_for('index'))
    other_purpose = request.form.get('other_purpose', '')
    certificate_options = [
    {'value': 'Cert. of Grades', 'label': 'Cert. of Grades'},
    {'value': 'Cert. of Enrolment', 'label': 'Cert. of Enrolment'},
    {'value': 'CAV / S.O Cert', 'label': 'CAV / S.O Cert'},
    {'value': 'Cert. of Earned Units', 'label': 'Cert. of Earned Units'}
    ]
    
    form_options = [
    {'value': 'Evaluation Form', 'label': 'Evaluation Form'},
    {'value': 'Subject Credit Form', 'label': 'Subject Credit Form'},
    {'value': 'Shifting Form', 'label': 'Shifting Form'},
    {'value': 'Completion Form', 'label': 'Completion Form'},
    {'value': 'AW / Adding /Dropping Form', 'label': 'AW / Adding /Dropping Form'}
    ]
    
    for_cav_request = [
    {'value': 'CAV', 'label': 'CAV'}
    ]
    
    other_options = [
    {'value': 'COM Reprint', 'label': 'COM Reprint'},
    {'value': 'Diploma', 'label': 'Diploma'},
    {'value': 'Cert. of Candidacy for Graduation', 'label': 'Cert. of Candidacy for Graduation'},
    {'value': 'Medium of Instruction', 'label': 'Medium of Instruction'}
    ]
    
    purpose_options = [
    {'value': 'For DFA', 'label': 'For DFA'},
    {'value': 'For CHED', 'label': 'For CHED'},
    {'value': 'For PNP', 'label': 'For PNP'},
    {'value': 'For Board Exam (PRC)', 'label': 'For Board Exam (PRC)'},
    {'value': 'For Scholarship', 'label': 'For Scholarship'},
    {'value': 'Others','id': 'Others', 'onClick': 'showHideTextBox()' ,'label': 'Others (Please Specify)'}
    ]
    
    if 'Others' in request.form.getlist('document'):
        show_other_textbox = True
    else:
        show_other_textbox = False
    formatted_request_num = f"{requestNum:06d}"
    print("Rendering home.html")
    return render_template('home.html',
                        formatted_request_num=formatted_request_num,
                        requests_db=requests_db,
                        notifications_db=notifications_db,
                        data=data, 
                        certificate_options=certificate_options,
                        form_options=form_options,
                        for_cav_request=for_cav_request,
                        other_options=other_options,
                        purpose_options=purpose_options,
                        other_purpose=other_purpose,
                        show_other_textbox=show_other_textbox
                        )
    
@app.route('/mark_successful', methods=['POST'])
def mark_successful():
    data = request.get_json()
    selected_ids = data.get('selectedIds', [])
    date_processed = datetime.now().replace(microsecond=0)
    current_user = session.get('username')
    if selected_ids:
        for request_id in selected_ids:
            formatted_request_num = f"{int(request_id):06d}"
            notifications_db.append({
                'processed': f'<strong>Request #{formatted_request_num}</strong> is marked as finished.',
                'admin_username': f'Processed by: {current_user}'
            })
            for req in ongoing_table_data:
                if req['requestNum'] == int(request_id):
                    req_copy = req.copy()
                    req_copy['successful'] = True
                    req_copy['date_processed'] = date_processed
                    req_copy['admin_username'] = current_user
                    finished_table_data.append(req_copy)
                    ongoing_table_data.remove(req)
                    break
    return redirect(url_for('ongoing_page', current_user=current_user))

@app.route('/mark_unsuccessful', methods=['POST'])
def mark_unsuccessful():
    data = request.get_json()
    selected_ids = data.get('selectedIds', [])
    reason_for_unsuccess = data.get('reasonForUnsuccess', '')
    date_processed = datetime.now().replace(microsecond=0)
    current_user = session.get('username')  # Get the current admin's username from session
    if selected_ids:
        for request_id in selected_ids:
            formatted_request_num = f"{int(request_id):06d}"
            notifications_db.append({
                'processed': f'<strong>Request #{formatted_request_num}</strong> is marked as unsuccessful.',
                'reason': reason_for_unsuccess,
                'admin_username': f'Processed by: {current_user}'  # Store the admin's username in the notification
            })
            for req in ongoing_table_data:
                if req['requestNum'] == int(request_id):
                    req_copy = req.copy()
                    req_copy['unsuccessful'] = True
                    req_copy['date_processed'] = date_processed
                    req_copy['reason_for_unsuccess'] = reason_for_unsuccess
                    req_copy['admin_username'] = current_user  # Store the admin's username in the request data
                    finished_table_data.append(req_copy)
                    ongoing_table_data.remove(req)
                    break
    return redirect(url_for('ongoing_page'))

@app.route('/edit_date', methods=['POST'])
def edit_date():
    if request.method == 'POST':
        data = request.json
        request_id = data.get('requestId')
        new_date = data.get('newDate')
        formatted_request_num = f"{int(request_id):06d}"
        for request_data in ongoing_table_data:
            if request_data['requestNum'] == int(request_id):
                request_data['claim_date'] = new_date
                notifications_db.append({
                'processed': f'Claim date for <strong>Request #{formatted_request_num}</strong> has been moved to <strong>{new_date}</strong>',
            })
                break
        # Redirect back to the ongoing page after updating the date
        return redirect(url_for('ongoing_page'))

@app.route('/pending_page', methods=['GET', 'POST'])
def pending_page():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('index'))
    admin_username = session['username']
    pending_requests_count = len(table_data)
    ongoing_requests_count = len(ongoing_table_data)

    return render_template('pendingRequests.html', 
                        table_data=table_data, 
                        pending_requests_count=pending_requests_count,
                        ongoing_requests_count=ongoing_requests_count,
                        admin_username=admin_username,
                        decrypt_data=decrypt_data
                        )

@app.route('/ongoing_page')
def ongoing_page():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('index'))
    admin_username = session['username']
    pending_requests_count = len(table_data)
    ongoing_requests_count = len(ongoing_table_data)
    return render_template('ongoingRequests.html',
                        ongoing_requests_count=ongoing_requests_count,
                        pending_requests_count=pending_requests_count,
                        table_data=table_data,
                        ongoing_table_data=ongoing_table_data,
                        admin_username=admin_username,
                        decrypt_data=decrypt_data
                        )



@app.route('/finished_page')
def finished_page():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('index'))
    admin_username = session['username']
    pending_requests_count = len(table_data)
    ongoing_requests_count = len(ongoing_table_data)
    return render_template('processedRequests.html',
                        finished_table_data=finished_table_data,
                        table_data=table_data,
                        pending_requests_count=pending_requests_count,
                        ongoing_requests_count=ongoing_requests_count,
                        admin_username=admin_username,
                        decrypt_data=decrypt_data
                        )

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.run(debug=True)