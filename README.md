# Penelope CTF Modules

This repository contains three custom modules for the Penelope reverse shell handler, designed specifically for competing in CTFs on the EchoCTF platform. These modules are maintained by me for personal use and for my team, but they are completely free and modifiable by anyone. I'm open to collaborations, pull requests (PRs), suggestions, or any contributions to improve them.

## Modules

### 1. Flag Claimer
This module automates the process of searching for and claiming flags on a compromised machine. It's particularly useful right after obtaining your first shell or after rooting the box. The module scans for existing flags and submits them to the CTF platform, providing feedback on whether the claims were successful.

#### Configuration
Add the following to your personal `~/.peneloperc` file:
```
ctf_rootpage = 'https://etsctf.net'
ctf_username = 'username'
ctf_password = 'password'
```
The module saves sessions, so subsequent runs should be faster starting from the second execution.

#### Usage
From the Penelope console:
```
run claim_flags
```

#### Screenshot
[Space for screenshot]

### 2. Send Shells
This module allows you to share reverse shells with team members, which is handy when one person has initial access and others will handle privilege escalation.

#### Configuration
Add the following to your `~/.peneloperc` file:
```
default_send_port = 9000
team_members = {
    'member1': '10.10.0.10',
    'member2': '10.10.0.11',
    'member3': '10.10.0.12',
    'member4': '10.10.0.13',
    'member5': '10.10.0.14',
}
```

#### Usage
From the Penelope console:
```
run send memberN
```
or
```
run send all
```

#### Screenshot
[Space for screenshot]

### 3. Custom LinPEAS
This module integrates a customized version of LinPEAS, tailored for the types of machines found in EchoCTF challenges. It includes integration with the ChatGPT API using a custom prompt to identify the most likely privilege escalation vectors.

#### Configuration
Add the following to your `~/.peneloperc` file:
```
openai_apikey = 'sk-proj-OfrhiiI5pgFXsdfdsfdsfdsfdsm914w1i-J539FagGizAf1k05I8_z-Tu9Vdfssdfdsfdsfdsfdsfsdfdsfsdfsdfsfdsfdsfdsfdsfhjjhgjggjg'
```
(Note: Use your real API key.)

#### Usage
From the Penelope console:
```
run linpeas
```
or (with AI integration):
```
run linpeas -a
```

#### Screenshot
[Space for screenshot]

## Integration with Penelope
To use these modules, you need my customized version of Penelope, which supports loading modules from a `modules` directory. You can find it here: [https://github.com/DystopianRescuer/penelope](https://github.com/DystopianRescuer/penelope).

After setting up Penelope:
1. Clone this repository.
2. Create symbolic links to the modules in your `~/.penelope/modules` directory. For example:
   ```
   ln -s /path/to/repo/flag_claimer.py ~/.penelope/modules/flag_claimer.py
   ln -s /path/to/repo/send_shells.py ~/.penelope/modules/send_shells.py
   ln -s /path/to/repo/custom_linpeas.py ~/.penelope/modules/custom_linpeas.py
   ```

## License and Contributions
These modules are released under an open-source license (e.g., MIT) and are free for anyone to use, modify, or distribute. Feel free to fork the repo, submit PRs, or open issues for bugs, features, or improvements. Collaboration is welcome!⏎
