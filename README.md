# password-strength-checker-and-generator-with-Tkinter

below are the sites/references I consulted alongside my thoughts and the rerlation the references have:

https://nordpass.com/secure-password/ (Used to benchmark how a password strength checker evaluates strong passwords)

Study material for Tkinter: https://www.geeksforgeeks.org/python/create-first-gui-application-using-python-tkinter/
https://www.geeksforgeeks.org/python/python-gui-tkinter/

Read up on regex documentation: https://docs.python.org/3/library/re.html

Top pwned passwords that I used to help create my banned passwords list: https://www.ncsc.gov.uk/static-assets/documents/PwnedPasswordsTop100k.txt 
The reason I hard-coded the banned passwords list as opposed to dynamically getting it via the API for pwned passwords form HaveIBeenPwned(https://api.pwnedpasswords.com/range/21BD1) is because the code does not use a hashing algorithm and all the passwords are hashed, though a script to automatically check these against Crackstation's stored cracked hashes could have most probably been made.

Common usernames:
https://isc.sans.edu/diary/30188
https://www.f5.com/labs/articles/threat-intelligence/spaceballs-security--the-top-attacked-usernames-and-passwords
https://wifihifi.com/top-200-most-popular-usernames-of-all-time/
https://weakpass.com/wordlists/usernames.txt

Repeated adjacent sequences (pa pattern of the same character appearing 4 times in a row) were penalised by a point as that reduces randomness/password entropy making it more easy to bruteforce. This was personally tested against NordPass' password strength metre.

The GUI and username field were added for visuualisation and or heightened realism (mainly visualisation in respect to the GUI). A backend daatabase to store user registrations could be created.

Lastly, any fixes, corrections or just words of general advice/feedback would be greatly appreciated. Thank you.

P.S.
Apologies if it is over commented, note taking helps memory retention and this project is not are not 1:1 with it's enterprise equivalent, thus certain things done here may or will not be done in inudstrial coding.
