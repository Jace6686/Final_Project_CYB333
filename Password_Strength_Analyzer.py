import re
import requests

# Function to evaluate password strength
def evaluate_password(password):
    length_score = len(password) >= 12
    complexity_score = bool(re.search(r'[A-Z]', password)) and bool(re.search(r'[a-z]', password)) and bool(re.search(r'[0-9]', password)) and bool(re.search(r'[\W_]', password))
    randomness_score = not bool(re.search(r'(.)\1{2,}', password))  # No more than 2 repeated characters

    return length_score, complexity_score, randomness_score

# Function to detect common attack patterns
def detect_attack_patterns(password):
    common_patterns = ['123456', 'password', 'qwerty', 'letmein', 'admin']
    for pattern in common_patterns:
        if pattern in password:
            return True
    return False

# Function to provide feedback and recommendations
def provide_feedback(password):
    feedback = []
    if len(password) < 12:
        feedback.append("Increase the length to at least 12 characters.")
    if not re.search(r'[A-Z]', password):
        feedback.append("Include at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        feedback.append("Include at least one lowercase letter.")
    if not re.search(r'[0-9]', password):
        feedback.append("Include at least one digit.")
    if not re.search(r'[\W_]', password):
        feedback.append("Include at least one special character.")
    if detect_attack_patterns(password):
        feedback.append("Avoid common patterns or sequences.")
    return feedback

# Function to check password against breach database
def check_breach(password):
    url = f"https://api.pwnedpasswords.com/range/{password[:5]}"
    response = requests.get(url)
    if response.status_code == 200:
        hashes = response.text.splitlines()
        for hash in hashes:
            if password[5:].upper() in hash:
                return True
    return False

# Function to score password strength
def score_password(password):
    length_score, complexity_score, randomness_score = evaluate_password(password)
    if length_score and complexity_score and randomness_score:
        return "Strong"
    elif length_score and (complexity_score or randomness_score):
        return "Moderate"
    else:
        return "Weak"

# Main function to analyze password
def analyze_password(password):
    score = score_password(password)
    feedback = provide_feedback(password)
    breached = check_breach(password)
    if breached:
        feedback.append("This password has been compromised in a data breach. Choose a different password.")
    return score, feedback

# Example usage
password = "P@ssw0rd123"
score, feedback = analyze_password(password)
print(f"Password Score: {score}")
print("Feedback:")
for item in feedback:
    print(f"- {item}")