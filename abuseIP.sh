#!/bin/bash

#now=$(printf '%(%d-%m-%Y_%H:%M)T\n')
API_KEY='ENTER API KEY FROM abuseipdb.com'

if ! dpkg -l | grep -q 'ipset-persistent'; then echo 'Requires ipset-persistent'; exit 1 ; fi
if ! dpkg -l | grep -q 'netfilter-persistent'; then echo 'Requires netfilter-persistent'; exit 1 ; fi
if ! dpkg -l | grep -q ' iptables-persistent'; then echo 'Requires iptables-persistent'; exit 1 ; fi
if ! dpkg -l | grep -q 'iptables'; then echo 'Requires iptables'; exit 1 ; fi
if ! which sed > /dev/null; then echo 'sed is required'; exit 1 ; fi
if ! which jq > /dev/null; then echo 'jq is required'; exit 1 ; fi
if ! which ipset > /dev/null; then echo 'ipset is required' ; exit 1 ; fi
if ! which fzf > /dev/null; then echo 'fzf is required' ; exit 1 ; fi
if ! which curl > /dev/null; then echo 'curl is required' ; exit 1 ; fi

function sense_check {
	[[ $verbose == True ]] && [[ $checkufw == True ]] && echo '-v verbose does not work with checking ufw -u' && exit 1
	[[ $fuzzy == True ]] && [[ $auto == True ]] && echo '-f fuzzy rules does not work with -A automation rules'
	[[ $flush == True ]] && [[ -z $fuzzy ]] || [[ -z $auto ]] && echo '-F flush rule requires fuzzy add rules -f option or -A option. See help with -h'
}

function check_ip {
  #checks ip and outputs to json file
	local json_file='newest_ip_check.json'
	curl -sG https://api.abuseipdb.com/api/v2/check \
		--data-urlencode "ipAddress=$1" \
		-d maxAgeInDays=90 \
		-d verbose \
		-H "Key: $API_KEY" \
		-H "Accept: application/json" > "$json_file"
	
	if [[ $verbose == True ]]; then
		jq -r '.data' "$json_file"
	else
		jq -r '.data|"\(.ipAddress) Confidence: \(.abuseConfidenceScore), Country: \(.countryCode), reported: \(.totalReports)"' "$json_file"
	fi
}

function check_ufw {
	# Get a list of current ips in block list.
	sudo ipset --list > ipset.list
	
	# empty test.ip file
	truncate -s 0 test.ip

	# build new test.ip file from ufw logs which checks against abuse ip databse
	sudo sed -En 's/.*SRC=([0-9\.]+)\s+DST.*/\1/p' /var/log/ufw.log | sort -u |
		while IFS= read -r ip; do
			check_ip "$ip" >> test.ip
		done
		
	# read in abuse ip database file and add ip to set if doesn't exist
	while IFS= read -r line; do
		set -- $line
		if [[ ${3/,/} -gt 20 && ${7/,/} -gt 5 ]]; then
      if ! grep -q "^${1}$" ipset.list && ! grep -Eq "^${1}.*timeout" ipset.list ; then
       	sudo ipset add myset "$1"
      fi
		fi
	done < test.ip
	}

function get_block {
	new_json="new.block.json"
	curl -sG https://api.abuseipdb.com/api/v2/blacklist \
		-d confidenceMinimum=90 \
		-H "Key: $API_KEY" \
		-H "Accept: application/json" > "$new_json"

	jq -r '.data[].ipAddress' "$new_json" > "${new_json}.ip"
}

function add_rules_fuz {
	# Get a list of current ips in block list.
	sudo ipset --list > ipset.list
	
	# If flush option is give on commandline, then flush ipset before adding new rules
	if [[ $flush == True ]]; then
		sudo ipset flush myset
		wait
	fi
	
	# fzf multiselect list for adding to ipset
	mapfile -t iplist < <(find "$PWD" -maxdepth 1 -type f -iname "*.ip" | fzf -m --reverse)

	for file in "${iplist[@]}"; do
		sort -u "$file" > "/tmp/${file##*/}"
		while IFS= read -r line; do
			set -- $line
			ip="$1"
			if ! grep -q "^${ip}$" ipset.list && ! grep -Eq "^${ip}.*timeout" ipset.list; then
				sudo ipset add myset "${ip}"
			fi
		done < "/tmp/${file##*/}"
	done
	sudo netfilter-persistent save
	exit
}
function add_rules_auto {
	# Get a list of current ips in block list.
	sudo ipset --list > ipset.list
	
	# If flush option is give on commandline, then flush ipset before adding new rules
	if [[ $flush == True ]]; then
		sudo ipset flush myset
		wait
	fi

	mapfile -t iplist < <(find "$PWD" -maxdepth 1 -type f -iname "*.ip")
		
	for file in "${iplist[@]}"; do
		sort -u "$file" > "/tmp/${file##*/}"
		while IFS= read -r ip ignore; do
			if ! grep -q "^${ip}$" ipset.list && ! grep -Eq "^${ip}.*timeout" ipset.list; then
				sudo ipset add myset "${ip}"
			fi
		done < "/tmp/${file##*/}"
	done
	sudo netfilter-persistent save
	exit
}

function help {
  cat << EOF

Option -c : check if ip is in databse, run ./abuseIP.sh -c 123.12.123.12
Option -g : Get 10,000 IP list from database, no further args required
Option -v : adds verbose to ip checking -c option only
Option -f : adds fuzzy file selection to adding ip rules to ipset. Requires -a option
Option -A : adds automation script for set files to update. Requires -a option.
Option -F : Flushes ipset rules, requires -a option.
Option -u : Check ufw logs and update IPSET - DO NOT USE -v VERBOSE!!
Option -h : Help tips :D

EOF
}

while getopts c:AFvghfu opt
do
  case "$opt" in
    c) checkerip=True ; check_ip_arg="$OPTARG";;
    g) getblock=True ;;
		u) checkufw=True ;;
		f) fuzzy=True ;;
		A) auto=True ;;
		F) flush=True ;;
		v) verbose=True ;;
    h) help ;;
    *) echo 'wrong selection, exit...' ;;
  esac
done

# Ensure no funny business
sense_check

# Run functions...
[[ $checkerip == True ]] && check_ip "$check_ip_arg"
[[ $getblock == True ]] && get_block
[[ $fuzzy == True ]] && add_rules_fuz
[[ $auto == True ]] && add_rules_auto
[[ $checkufw == True ]] && check_ufw
