## The why..

Gather data from abuse IP database and update firewall rules using ipset

This script is fairly recent, so might need some modifications.

## Dependencies....

```bash
apt install ipset-persistent netfilter-persistent iptables-persistent iptables sed jq ipset fzf curl
```

I've set this up to work alongside crowdsec, so you get another way of veriying your traffic.

## setup ipset and iptables

Requires ipset list, 2 week timeout included...

```bash
ipset create myset hash:ip timeout 1209600
ipset create myset6 hash:net family inet6 timeout 1209600
```

Requires iptables rule 

```bash
iptables -I INPUT -m set --match-set myset src -j DROP
ip6tables -I INPUT -m set --match-set myset6 src -j DROP
```

Also requires to make sure iptables is persistent after new rule

```bash
sudo dpkg-reconfigure iptables-persistent
```

## This script..

Githuib link..

```bash
git clone https://github.com/jonnypeace/ip-abuse-bash.git
```

You will also need an API key from abuseipdb.com and sign up for an account.

Store your api.key in the same folder as this script, with filename api.key

This script will save files in it's current directory, so maybe best keeping in this git directory

You will want to modify the variable for the location you are using for this repo.

```bash
ip_file_path="$HOME/git/ip-abuse-bash"
```

Run this for some help...

```bash
./abuseIP.sh -h
```

Output:

```bash
On first run you will need the 10,000 IPs, so run with -g flag.

Option -c : check if ip is in databse, run ./abuseIP.sh -c 123.12.123.12
Option -g : Get 10,000 IP list from database, no further args required
Option -v : adds verbose to ip checking -c option only
Option -f : adds fuzzy file selection to adding ip rules to ipset. Any file ending in .ip
Option -A : adds automation script for set files to update, any file ending in .ip
Option -F : Flushes ipset rules, requires -f or -A option.
Option -u : Check ufw logs and update IPSET - DO NOT USE -v VERBOSE!!
Option -h : Help tips :D
```

There are not a lot of options, and for automation in crontab, i run...

```bash
0 */3 * * * /home/jonny/ip-abuse-bash/abuseIP.sh -gA > /dev/null && echo 'database updated and added to ipset'
*/30 * * * * /home/jonny/ip-abuse-bash/abuseIP.sh -u > /dev/null && echo 'ufw log checked and ips added to ipset'
```