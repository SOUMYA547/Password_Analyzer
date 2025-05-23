import re
import math
import hashlib
import requests

COMMON_PASSWORDS = {
    "123456", "password", "qwerty", "abc123", "12345678", "1234", "987654321",
    "1234567", "87654321", "7654321", "123abc", "asdfgh", "jhgfdsa", "654321", "543210"
}

def calculate_entropy(password):
    charset = 0
    if re.search(r'[a-z]', password):
        charset += 26
    if re.search(r'[A-Z]', password):
        charset += 26
    if re.search(r'\d', password):
        charset += 10
    if re.search(r'[!@#$%^&*(),./<>?:";]', password):
        charset += 32
    entropy = len(password) * math.log2(charset) if charset else 0
    return round(entropy, 2)

def check_breach(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return int(count)
    except:
        return -1
    return 0

def password_strength(password):
    length = len(password)
    score = 0
    recommendations = []

    if password.lower() in COMMON_PASSWORDS:
        recommendations.append("Avoid using common passwords.")
        entropy = calculate_entropy(password)
        return "Very Weak", recommendations, entropy

    if length < 6:
        recommendations.append("Password is too short. Use at least 12 characters.")
        entropy = calculate_entropy(password)
        return "Very Weak", recommendations, entropy
    elif length < 8:
        score += 1
        recommendations.append("Consider increasing password length.")
    elif length >= 12:
        score += 2

    if re.search(r'[a-z]', password): score += 1
    else: recommendations.append("Add lowercase letters.")
    
    if re.search(r'[A-Z]', password): score += 1
    else: recommendations.append("Add uppercase letters.")
    
    if re.search(r'\d', password): score += 1
    else: recommendations.append("Add digits.")
    
    if re.search(r'[!@#$%^&*(),./?{}|<>]', password): score += 1
    else: recommendations.append("Add special characters like !@#$%^&*.")

    if re.fullmatch(r'(.)\1+', password):
        recommendations.append("Avoid repetitive characters.")
        score -= 1

    if re.search(r'(abc|123|qwerty|asdf)', password.lower()):
        recommendations.append("Avoid sequential or keyboard patterns.")
        score -= 1

    # Cap score
    score = max(0, min(score, 6))

    if score <= 2:
        strength = "Weak"
    elif score == 3:
        strength = "Moderate"
    elif score == 4:
        strength = "Strong"
    elif score == 5:
        strength = "Medium Strong"
    elif score == 6:
        strength = "Very Strong"
    else:
        strength = "Impossible to be cracked"

    entropy = calculate_entropy(password)
    return strength, recommendations, entropy

def main():
    password = input("Enter a password to analyze: ")
    strength, tips, entropy = password_strength(password)
    breach_count = check_breach(password)

    print(f"\n🔒 Password Strength: {strength}")
    print(f"🔑 Entropy: {entropy} bits")

    if tips:
        print("\n📋 Recommendations:")
        for tip in tips:
            print(f" - {tip}")

    if breach_count > 0:
        print(f"\n⚠️ Found in {breach_count} data breaches. Do NOT use this password.")
    elif breach_count == 0:
        print("\n✅ Not found in known breaches.")
    else:
        print("\n⚠️ Could not check for breaches (offline or API limit).")

if __name__ == "__main__":
    main()
