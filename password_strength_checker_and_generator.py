import tkinter as tk # Importing tkinter and renaming it to tk for convenience
from tkinter import messagebox # Importing messagebox from tkinter for displaying messages
import random
import string
import re

banned_passwords = [
    "password", "123456", "12345678", "123456789", "12345", "qwerty", "abc123",
    "letmein", "monkey", "111111", "iloveyou", "admin", "welcome", "password1",
    "1234567", "123123", "qwertyuiop"
]

banned_usernames = [
    "admin", "administrator", "root", "user", "guest", "test", "username", "David",
    "sysadmin", "superuser", "Alex", "manager"
]

def password_generator(min_length, numbers=True, special_characters=True):
    letters = string.ascii_letters  # All uppercase and lowercase letters in ASCII
    digits = string.digits # All digits in ASCII (0-9)
    special_chars = string.punctuation  # Special characters

    characters = letters # all passwords will contain letters by default
    if numbers: # Include digits if specified
        characters += digits # Append the digits to the characters string
    if special_characters: # Include special characters if specified
        characters += special_chars # Append the special characters to the characters string
    
    password = "" #Initialise an empty password string
    meets_criteria = False #Flag to check if the password meets the criteria
    has_number = False #Flag to check if the password contains a number
    has_special = False #Flag to check if the password contains a special character

    while not meets_criteria or len(password) < min_length:
        new_char = random.choice(characters) # Randomly select a character from the characters string
        password += new_char # Append the new character to the password string

        if new_char in digits: # Check if the new character is a digit
            has_number = True # Set the has_number flag to True
        elif new_char in special_chars: # Check if the new character is a special character
            has_special = True
        
        meets_criteria = True
        if numbers and not has_number: # If numbers are required and no number is found, then it does not meet the criteria. Hence, set meets_criteria to False.
            meets_criteria = False
        if special_characters and not has_special: # If special characters are required and no special character is found. This is done regardless of if the previous if statement was true or false.
            meets_criteria = False
        
    return password # Return the generated password once it meets the criteria and is of the minimum length

# Function to calculate password strength, passwords are scored based on length, character variety, and banned words
def password_strength(password):
    score = 0
    pwd_length = len(password)
    if pwd_length >= 8 and pwd_length <= 10:
        score += 1
    elif pwd_length > 10 and pwd_length <= 14:
        score += 2
    elif pwd_length > 14:
        score += 3
    
    if password.lower() not in banned_passwords: # force password to be lowercase to match the banned passwords list, which is also in lowercase
        score += 1

    if re.search(r"(?=.*[a-z]).*", password):
        score += 1
    if re.search(r"(?=.*[A-Z]).*", password):
        score += 1
    if re.search(r"(?=.*\d).*", password): # Check for at least one digit, \d for unicode digits/strings since it is more inclusive and VSCode uses UTF-8 encoding
        score += 1 # If you have at least a digit, add 1 to the score. More than one digit does not increase the score.
    if re.search(r"(?=.*[!@#$%^&*()_+{}|:<>?]).*", password): # Check for at least one special character
        score += 1

    # Penalize for 4 or more repeating characters in a row
    if re.search(r"(.)\1{3,}", password): # quantifier {3,} means 3 or more occurrences of the preceding character, thus it will match 4 or more adjacent repeating characters
        score -= 1 # penalised due to decreasing password entropy and establishing a pattern that is easy to guess

    return score

# Function to classify password strength
def classify_password_strength(score):
    if score >= 7:
        return "Strong"
    elif score >= 5:
        return "Moderate"
    else:
        return "Weak"


# --- Tkinter GUI Implementation ---
def run_gui():
    root = tk.Tk() # Create the root/main window
    root.title("Password Strength Checker & Generator") # Title of the window
    root.geometry("400x400") # Set the size of the window to 400x400 pixels

    # Username input section
    tk.Label(root, text="Enter your username:").pack() # Create a label for the username input
    username_var = tk.StringVar()
    username_entry = tk.Entry(root, textvariable=username_var)
    username_entry.pack()

    # Password (user input)
    tk.Label(root, text="Enter your password (8-64 chars):").pack()
    password_var = tk.StringVar()
    password_entry = tk.Entry(root, textvariable=password_var, show="*")
    password_entry.pack()

    # Password confirmation
    tk.Label(root, text="Re-enter your password:").pack()
    confirm_var = tk.StringVar()
    confirm_entry = tk.Entry(root, textvariable=confirm_var, show="*")
    confirm_entry.pack()

    # Or generate password
    tk.Label(root, text="--- OR ---").pack(pady=5)
    tk.Label(root, text="Generate a random password:").pack()
    minlen_var = tk.StringVar(value="8")
    tk.Label(root, text="Minimum length (8+):").pack()
    minlen_entry = tk.Entry(root, textvariable=minlen_var)
    minlen_entry.pack()
    numbers_var = tk.BooleanVar(value=True)
    specials_var = tk.BooleanVar(value=True)
    tk.Checkbutton(root, text="Include numbers", variable=numbers_var).pack()
    tk.Checkbutton(root, text="Include special characters", variable=specials_var).pack()

    result_label = tk.Label(root, text="", fg="blue")
    result_label.pack(pady=10)

    def check_password():
        username = username_var.get().strip()
        password = password_var.get()
        confirm = confirm_var.get()
        if username in banned_usernames:
            messagebox.showerror("Error", "This username is not allowed.")
            return
        if len(username) < 1 or len(username) > 30:
            messagebox.showerror("Error", "Username must be 1-30 characters.")
            return
        if len(password) < 8 or len(password) > 64:
            messagebox.showerror("Error", "Password must be 8-64 characters.")
            return
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        score = password_strength(password)
        strength = classify_password_strength(score)
        result_label.config(text=f"Password strength: {strength} (score: {score})")
        messagebox.showinfo("Success", "Password saved successfully.")

    def generate_password():
        try:
            minlen = int(minlen_var.get())
            if minlen < 8:
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Minimum length must be at least 8.")
            return
        password = password_generator(minlen, numbers_var.get(), specials_var.get())
        score = password_strength(password)
        strength = classify_password_strength(score)
        result_label.config(text=f"Generated password: {password}\nStrength: {strength} (score: {score})")

    tk.Button(root, text="Check Password", command=check_password).pack(pady=5)
    tk.Button(root, text="Generate Password", command=generate_password).pack(pady=5)

    root.mainloop()

#call the run_gui function to start the GUI application
# This function creates the main window, sets up the layout, and defines the functionality for checking password strength and generating passwords.
# The GUI includes input fields for username and password, options for generating a random password, and buttons to check the password strength or generate a new password. It also includes error handling for invalid inputs and displays the results of password strength and generated results in a label.
if __name__ == "__main__": # This line ensures that the run_gui function is called only when this script is run directly, not when imported as a module.
    run_gui()