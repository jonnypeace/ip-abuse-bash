Gather data from abuse IP DB and update firewall rules using ipset

This script is still rough around the edges and still requires a lot of testing.

Dependencies....

```bash
apt install ipset-persistent netfilter-persistent iptables-persistent iptables sed jq ipset fzf curl
```

I've set this up to work alongside crowdsec, so you will see some syntax supporting this alongside... mainly for the timeout conditions.

Requires ipset list...

```bash
ipset create myset hash:ip
```

Requires iptables rule 

```bash
iptables -I INPUT -m set --match-set myset src -j DROP
```

Also requires to make sure iptables is persistent after new rule

```bash
sudo dpkg-reconfigure iptables-persistent
```

Store your api.key in the same folder as this script, with filename api.key

This script will save files in it's current directory, so maybe best keeping in this git directory

You will also need an API key from abuseipdb.com and sign up for an account
