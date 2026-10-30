from urllib.parse import urljoin

COMMON_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("test", "test"),
    ("user", "password")
]

def is_login_form(form):
    inputs = form.get("inputs", [])
    
    has_password = False
    has_username = False
    
    # Keywords that suggest a login page
    username_keywords = ["user", "email", "login", "username", "uid", "account", "name"]
    password_keywords = ["pass", "password", "pwd", "secret"]

    for inp in inputs:
        field_name = inp.get("name", "").lower()
        field_type = inp.get("type", "").lower()
        field_id = inp.get("id", "").lower()

        if field_type == "password":
            has_password = True

        if any(kw in field_name for kw in password_keywords) or \
           any(kw in field_id for kw in password_keywords):
            has_password = True

        if field_type == "email":
            has_username = True

        if any(kw in field_name for kw in username_keywords) or \
           any(kw in field_id for kw in username_keywords):
            has_username = True
            
    return has_password and has_username

def test_login_form(session, form):

    target_url = form["url"]
    action = form["action"]
    method = form["method"]

    url = urljoin(target_url, action)

    for username, password in COMMON_CREDENTIALS:

        data = {}

        for field in form["inputs"]:
            name = field["name"]

            if "user" in name.lower():
                data[name] = username
            elif "pass" in name.lower():
                data[name] = password
            else:
                data[name] = field["value"]

        if method == "POST":
            response = session.post(url, data=data)
        else:
            response = session.get(url, params=data)

        # Very simple detection logic
        if "logout" in response.text.lower() or "welcome" in response.text.lower():
            print("Weak credential found!")
            print(username, password)