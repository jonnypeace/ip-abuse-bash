#!/bin/bash

# 2 week timeout in seconds
timeout='1209600'

# file-path-source ---- once ipabuse.conf updated, run setup.sh

#now=$(printf '%(%d-%m-%Y_%H:%M)T\n')
API_KEY=$(< "$my_abuse_API")

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
  [[ $flush == True ]] && [[ -z $fuzzy ]] || [[ $flush == True ]] && [[ -z $auto ]] && echo '-F flush rule requires fuzzy add rules -f option or -A option. See help with -h'
}

function check_ip {
  #checks ip and outputs to json file
  #local json_file='/home/jonny/ip-abuse-bash/newest_ip_check.json'
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
  #ipsets_file='/home/jonny/ip-abuse-bash/ipset.list'
  sudo ipset --list > "$ipsets_file"
  
  #testip='/home/jonny/ip-abuse-bash/test.ip'
  # empty test.ip file
  truncate -s 0 "$testip"

  # build new test.ip file from ufw logs which checks against abuse ip databse
  sudo sed -En 's/.*SRC=([0-9\.]+)\s+DST.*/\1/p' /var/log/ufw.log | sort -u |
    while IFS= read -r ip; do
      check_ip "$ip" >> "$testip"
    done
    
  # coounter for number of ips
  a=0
  ip_num=$(wc -l "$testip" | cut -d ' ' -f1)
  # read in abuse ip database file and add ip to set if doesn't exist
  while IFS= read -r line; do
    set -- $line
    ip="$1"
    if [[ ${3/,/} -gt 20 && ${7/,/} -gt 5 ]]; then
      # This currently filters out ipv6, but later versions i'll deal with this...
      if [[ ! $ip =~ [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} ]]; then
        printf '%s\n' "$ip might be an ipv6 address. Will support in a future version"
        (( ip_num-- ))
        continue
      fi
      if ! grep -q "^${1}$" "$ipsets_file" && ! grep -Eq "^${1}.*timeout" "$ipsets_file" ; then
         sudo ipset add myset "$1" timeout "$timeout"
      fi
      (( a++ ))
      printf '%s\033[0K\r' "Progressing ips $a of $ip_num total"
    fi
  done < "$testip"
  printf '\n'
  }

function get_block {
  #new_json="/home/jonny/ip-abuse-bash/new.block.json"
  curl -sG https://api.abuseipdb.com/api/v2/blacklist \
    -d confidenceMinimum=90 \
    -H "Key: $API_KEY" \
    -H "Accept: application/json" > "$new_json"

  jq -r '.data[].ipAddress' "$new_json" > "${new_json}.ip"
}

function add_rules_fuz {
  # Get a list of current ips in block list.
  #ipsets_file='/home/jonny/ip-abuse-bash/ipset.list'
  sudo ipset --list > "$ipsets_file"
  
  # If flush option is give on commandline, then flush ipset before adding new rules
  if [[ $flush == True ]]; then
    sudo ipset flush myset
    wait
  fi
  
  # fzf multiselect list for adding to ipset
  mapfile -t iplist < <(find "$ip_file_path" -maxdepth 1 -type f -iname "*.ip" | fzf -m --reverse)
  # coounters for file number b and ip number a
  a=0
  b=1
  file_num="${#iplist[@]}"
  for file in "${iplist[@]}"; do
    sort -u "$file" > "/tmp/${file##*/}"
    ip_line=$(wc -l "/tmp/${file##*/}" | cut -d ' ' -f1)
    ip_num=$(( ip_num + ip_line ))
    while IFS= read -r line; do
      set -- $line
      ip="$1"
      if [[ $# == 1 || ${3/,/} -gt 20 && ${7/,/} -gt 5 ]]; then
        # This currently filters out ipv6, but later versions i'll deal with this...
        if [[ ! $ip =~ [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} ]]; then
          printf '%s\n' "$ip might be an ipv6 address. Will support in a future version"
          (( ip_num-- ))
          continue
        fi
        if ! grep -q "^${ip}$" "$ipsets_file" && ! grep -Eq "^${ip}.*timeout" "$ipsets_file"; then
          sudo ipset add myset "${ip}" timeout "$timeout"
        fi
        (( a++ ))
        printf '%s\033[0K\r' "Progressing file $b of $file_num, ips $a of $ip_num total"
      fi
    done < "/tmp/${file##*/}"
    (( b++ ))
  done
  printf '\n'
  sudo netfilter-persistent save
  exit
}
function add_rules_auto {
  # Get a list of current ips in block list.
  #ipsets_file='/home/jonny/ip-abuse-bash/ipset.list'
  sudo ipset --list > "$ipsets_file"
  
  # If flush option is give on commandline, then flush ipset before adding new rules
  if [[ $flush == True ]]; then
    sudo ipset flush myset
    wait
  fi

  mapfile -t iplist < <(find "$ip_file_path" -maxdepth 1 -type f -iname "*.ip")
  # counters for file number b and ip number a
  a=0  
  b=1
  file_num="${#iplist[@]}"
  for file in "${iplist[@]}"; do
    sort -u "$file" > "/tmp/${file##*/}"
    ip_line=$(wc -l "/tmp/${file##*/}" | cut -d ' ' -f1)
    ip_num=$(( ip_num + ip_line ))
    while IFS= read -r line; do
      set -- $line
      ip="$1"
      if [[ $# == 1 || ${3/,/} -gt 20 && ${7/,/} -gt 5 ]]; then
        # This currently filters out ipv6, but later versions i'll deal with this...
        if [[ ! $ip =~ [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} ]]; then
          printf '%s\n' "$ip might be an ipv6 address. Will support in a future version"
          (( ip_num-- ))
          continue
        fi
        if ! grep -q "^${ip}$" "$ipsets_file" && ! grep -Eq "^${ip}.*timeout" "$ipsets_file"; then
          sudo ipset add myset "${ip}" timeout "$timeout"
        fi
        (( a++ ))
        printf '%s\033[0K\r' "Progressing file $b of $file_num, ips $a of $ip_num total"
      fi
    done < "/tmp/${file##*/}"
    (( b++ ))
  done
  printf '\n'
  sudo netfilter-persistent save
  exit
}

function help {
  cat << EOF

On first run you will need the 10,000 IPs, so run with -g flag.

Option -c : check if ip is in databse, run ./abuseIP.sh -c 123.12.123.12
Option -g : Get 10,000 IP list from database, no further args required
Option -v : adds verbose to ip checking -c option only
Option -f : adds fuzzy file selection to adding ip rules to ipset. Any file ending in .ip
Option -A : adds automation script for set files to update, any file ending in .ip
Option -F : Flushes ipset rules, requires -f or -A option.
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
[[ $checkufw == True ]] && check_ufw
[[ $fuzzy == True ]] && add_rules_fuz || [[ $auto == True ]] && add_rules_auto
