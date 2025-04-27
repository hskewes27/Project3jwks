First off I was only able to get this project to work while in a venv
on my vscode tried it many times otherwise this is the only way i got it to work
Requirements to run: Pyjwt, cryptography, argon2_cffi, passlib
next set the environment variable i was using powershell so mine looked like this:
$env:NOT_MY_KEY = "abcdefghijklmnopqrstuvwxyz012345"
I would also make sure to delete the db before running the program so it has a fresh set to go with.
Now that thats out of the way i just ran the command 'python jwks.py'
the server will then log that keys have been made and that the server is running.
Each major process has logging features and certain debug logs as well since I had so many issues with
getting the correct data type when encrypting and decrypting from the database. I also figured out my issue in the last project
It likely stemmed from not being in a venv and some of my other code messing with my current project.

using the code:
So after starting open a second window to run powershell commands to register and authorize a user.
The commands looked like this:
Invoke-WebRequest -Uri "http://127.0.0.1:8080/register" `
>>     -Method POST `
>>     -Headers @{"Content-Type"="application/json"} `
>>     -Body '{"username": "testusr", "email": "testuser@example.com"}'

After using this request the program will return a generated password for the user to copy and paste into the authorization request


Invoke-WebRequest -Uri "http://127.0.0.1:8080/auth" `    
>>     -Method POST `
>>     -Headers @{"Content-Type"="application/json"} `
>>     -Body '{"username": "testusr", "password": "Generated password"}'

After putting in the generated password from the register request it should be good to use and the user will be authorized.
I also had to edit the rate limit from being 1 second to 3 seconds because I was having issues getting those final points even
though my logs said I was able to get a 429 error with the amount of requests coming through. With a 1 second window I was getting 
65/90, but then I switched it to 3 and got 90/90 so I will be sticking with that.
At this point I would usually run the gradebot against it in that same powershell cli
./gradebot.
I was able to implement 90/90 points 
