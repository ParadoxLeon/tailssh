## Simple script that scans for available machines with ```tailscale status``` and creates an SSH connection.

### tailssh Install
1. Download the script
2. Install python3
3. run the script :)
4. (optional Linux) add an alias ```echo "alias tailssh='python3 ~/tailssh.py'" >> ~/.bashrc``` then reload ```source ~/.bashrc``` now you only have to type tailssh
5. (optional Windows) type ```notepad $PROFILE``` into you're powershell an add this to you're file:
```
function tailssh {
    python "C:\path\to\the\script\tailssh.py"
}
```
## to save passwords use the script ```tailsshWITH_PASSWD_SAVE.py```. LINUX ONLY
It saves the password to the system keyring
### dependencies
- pip keyring
- sshpass
