#!//bin/bash
############
#Version 1.0.7
#####################################################################
#Created by Felipe Legorreta, Rapid7 InsightIDR technical specialist#
#####################################################################
############################################################
###Don't forget to set the environment! (Domain, ip, paths)#
############################################################
inputad=logs/ad.log
inputfw=logs/asa.log
inputav=logs/symantec.log
inputvpn=logs/asavpn.log
inputids=logs/snort.log
inputdns=logs/infobloxdns.log
inputdhcp=logs/infobloxdhcp.log
collectorip=127.0.0.1
domain=MyDomain
IFS=,

##############################################################################################################################################################
#Each user will be chosen randomly and will generate a random amount of logs, or perhaps not generating logs at all, it all depends on the threshold settings#
#In addition to that, the script will generate more traffic during 9 to 5 hours, and it will also generate asset logins in the AD during 9-10AM and 1-2PM#####
##############################################################################################################################################################

###Starting an infinite loop###
echo "Simulator Started..."
while true; do echo 'Press CTRL+C  or CTRL+Z to STOP!';
currenttime=$(date +%H)

###This will shuffle the existing user list so that it is different with every iteration###
shuf users.txt -o users.txt
input=users.txt

if [[ "$currenttime" > 9 || "$currenttime" < 17 ]]; then
sleep 3;
else
sleep 20;
fi
while read -r uname uip utype umac uwstation
do
	echo "Simulating activity for.... $uname ($utype user) -> $uip"

		###AD login logs (in the morning and after lunch)###
		if [[ "$currenttime" > 9 || "$currenttime" < 10 ]]; then
				today=$(date +"%b %d %T")
				tstamp=$(date +"%a %b %d %T %Y")
		printf "<14>"$today" Simulator_DC MSWinEventLog\t1\tSecurity\t499\t"$tstamp"\t4624\tMicrosoft-Windows-Security-Auditing\t${domain}\\${uname}\tN/A\tSuccess Audit\tSimulator_DC\tLogon\t\tAn account was successfully logged on.    Subject:   Security ID:  S-1-0-0   Account Name:  -   Account Domain:  -   Logon ID:  0x0    Logon Type:   3    New Logon:   Security ID:  S-1-5-21-3070936213-306261907-1348773959-4781   Account Name:  ${uname}   Account Domain:  ${domain}   Logon ID:  0x41a020   Logon GUID:  {805A4260-F084-5BD7-FDA9-5DC99C801F5F}    Process Information:   Process ID:  0x0   Process Name:  -    Network Information:   Workstation Name:  ${uwstation}  Source Network Address: ${uip}   Source Port:  56386    Detailed Authentication Information:   Logon Process:  Kerberos   Authentication Package: Kerberos   Transited Services: -   Package Name (NTLM only): -   Key Length:  0    This event is generated when a logon session is created. It is generated on the computer that was accessed.    The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.    The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).    The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.    The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.    The authentication information fields provide detailed information about this specific logon request.\t440" | nc -w1 -u $collectorip 10006
		fi


		if [[ "$currenttime" > 12 || "$currenttime" < 13 ]]; then
				today=$(date +"%b %d %T")
				tstamp=$(date +"%a %b %d %T %Y")
		printf "<14>"$today" Simulator_DC MSWinEventLog\t1\tSecurity\t499\t"$tstamp"\t4624\tMicrosoft-Windows-Security-Auditing\t${domain}\\${uname}\tN/A\tSuccess Audit\tSimulator_DC\tLogon\t\tAn account was successfully logged on.    Subject:   Security ID:  S-1-0-0   Account Name:  -   Account Domain:  -   Logon ID:  0x0    Logon Type:   3    New Logon:   Security ID:  S-1-5-21-3070936213-306261907-1348773959-4781   Account Name:  ${uname}   Account Domain:  ${domain}   Logon ID:  0x41a020   Logon GUID:  {805A4260-F084-5BD7-FDA9-5DC99C801F5F}    Process Information:   Process ID:  0x0   Process Name:  -    Network Information:   Workstation Name:  ${uwstation}  Source Network Address: ${uip}   Source Port:  56386    Detailed Authentication Information:   Logon Process:  Kerberos   Authentication Package: Kerberos   Transited Services: -   Package Name (NTLM only): -   Key Length:  0    This event is generated when a logon session is created. It is generated on the computer that was accessed.    The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.    The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).    The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.    The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.    The authentication information fields provide detailed information about this specific logon request.\t440" | nc -w1 -u $collectorip 10006
		fi

		###This will send Firewall logs up to 5 logs per user###
		today=$(date +"%b %d %Y %T:")
		for((n=1;n<=$(( 1 + $RANDOM % 5));n++))
			do
			replace="${replace/uname/$uname}"
			replace=$(shuf -n 1 $inputfw)
			echo $today".000 Simulator_ASA: ${replace/uip/$uip}" | nc -w1 -u $collectorip 10001
		done

		###This will send AD logs up to 1 logs per user###
			today=$(date +"%b %d %T")
			tstamp=$(date +"%a %b %d %T %Y")
				for((n=0;n<=$(( -1 + $RANDOM % 2));n++))
					do
						replace=$(shuf -n 1 $inputad)
						replace="${replace/tstamp/$tstamp}"
						replace="${replace/uname/$uname}"
						replace="${replace/uname/$uname}"
						replace="${replace/udomain/$domain}"
						replace="${replace/udomain/$domain}"
						replace="${replace/uwstation/$uwstation}"
						echo $today".000 Simulator_DC: ${replace/uip/$uip}"
						printf $today".000 Simulator_DC: ${replace/uip/$uip}" | nc -w1 -u $collectorip 10006
					done

		###This will send VPN logs for VPN users up to 3 events per user###
		if [ $utype == 'VPN' ]; then
			for((n=0;n<=$(( -1 + $RANDOM % 3));n++))
			do
			replace=$(shuf -n 1 $inputvpn)
			uip=$(awk -F"." '{print $1"."$2"."7"."$4}'<<<$uip)
			replace="${replace/uip/$uip}"
			echo $today".000 Simulator_VPN: ${replace/uname/$uname}" | nc -w1 -u $collectorip 10001
			done
		fi

		###This will send IDS logs up to 1 per user###
		today=$(date +"%b %d %Y %T ")
		for((n=0;n<=$(( -1 + $RANDOM % 2));n++))
			do
			replace=$(shuf -n 1 $inputids)
			echo $today"Simulator_IDS suricata[9354]: ${replace/uip/$uip}" | nc -w1 -u $collectorip 10003
		done

		###This will send DNS logs up to 4 per user###
		today=$(date +"%b %d %Y %T ")
		for((n=0;n<=$(( -1 + $RANDOM % 4));n++))
			do
			replace=$(shuf -n 1 $inputdns)
			echo "Simulator_DNS "$today" 0.0.0.0  ${replace/uip/$uip}" | nc -w1 -u $collectorip 10004
		done

		###This will send DHCP logs up to 4 per user###
		today=$(date +"%b %d %Y %T ")
		for((n=0;n<=$(( -1 + $RANDOM % 4));n++))
			do
			replace=$(shuf -n 1 $inputdhcp)
			replace="${replace/umac/$umac}"
			replace="${replace/uwstation/$uwstation}"
			echo $today"Simulator_DHCP ${replace/uip/$uip}" | nc -w1 -u $collectorip 10005
		done

		###This will send AV logs up to 1 per user###
		today=$(date +"%b %d %Y %T ")
		for((n=0;n<=$(( -1 + $RANDOM % 2));n++))
			do
			replace=$(shuf -n 1 $inputav)
			replace="${replace/uname/$uname}"
			replace="${replace/tstamp/$today}"
			echo $today" ${replace/uwstation/$uwstation}" | nc -w1 -u $collectorip 10007
		done

done <"$input"
done
