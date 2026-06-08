

On system health:

#What aspects of a running Linux system tell you whether it is healthy or under stress? ss tulnp, htop/hop, df -h, uptime 
Basically if there's a queue of actions (Load average above 4.0), or sudden spike in CPU usage. 
Where does Linux expose this information? Think about both commands and files in /proc.
What values or thresholds would indicate a problem worth alerting on?
/
├── bin/        → Essential command binaries (ls, cp, cat...)
├── sbin/       → System binaries (for root/admin use)
├── etc/        → Configuration files (all system settings live here)
├── home/       → Home directories for regular users
│   ├── alice/
│   └── bob/
├── root/       → Home directory for the root user
├── var/        → Variable data (logs, mail, temporary spool files)
│   └── log/    → System and application log files  ###### syslog ?? #######
├── tmp/        → Temporary files (writable by everyone, cleaned on reboot)
├── usr/        → User programs and libraries
│   ├── bin/    → Most user commands
│   └── lib/    → Shared libraries
├── proc/       → Virtual filesystem — info about running processes  ######## here #####
├── dev/        → Device files (disks, terminals, USB devices)
├── opt/        → Optional/third-party software
└── mnt/        → Mount points for external filesystems

If you were writing a Python or Bash script for your HIDS, these are the files you would "read":
/proc/loadavg: Shows the system load over 1, 5, and 15 minutes.
/proc/meminfo: Detailed RAM stats (Total, Free, Available, Swap).
/proc/stat: Raw CPU ticks (used to calculate CPU percentage).
/proc/net/dev: Statistics on network packets sent/received.
/proc/[PID]/status: Specific health data for a single process (replace [PID] with a number).

🚨 Thresholds: When should your HIDS alert?
A HIDS that alerts on everything is a nuisance (we call this Alert Fatigue). For a solid starting point, use these thresholds:

###  CPU Usage (> 85% for 5 mins): Short spikes are fine (like starting a program). A sustained 85%+ suggests a runaway process, a brute-force attack, or a cryptominer.
###  Load Average (> Cores x 1.5): If you have 2 cores and your load is 3.0, your system is struggling to keep up with tasks.
###  Disk Usage (> 90%): If a disk hits 100%, services crash (this is a "Self-Inflicted DoS"). Alert at 90% so you have time to react.
###  Swap Usage (> 10%): If the system starts leaning on Swap memory, performance will tank. This is usually the first sign of a "Memory Leak" in a compromised application.

find / -mtime -7 -type f 2>/dev/null | grep -v /proc (Find any files modified in the last week in the /proc)


On users and activity:

How does Linux record who has logged in, when, and from where?
Where are these records stored? Which commands let you read them?
What user activity would look suspicious on a production server?

who: Gives you a quick list of users, their terminal (tty), and their login time.
last: Pulls from wtmp. It’s your "time machine." If you see a login from an IP address in a country where your company doesn't operate, that's your first red flag.
lastb: This is essential for HIDS. It shows you the username and IP of every failed attempt. If you see 500 failed attempts for the user admin, someone is running a brute-force script.

mostly stored in the var/log syslog 
On a production server, "Normal" is very predictable. Anything outside that predictable path is suspicious.
need to control for : 
-impossible timestamps 
-a sudden new resident (count the amount of regular users)
-Privilege Escalation (The sudo trail)
-Unusual Source IPs

On processes:

How do you get a full picture of what is running on a system?
What would make a process look suspicious — not just what it is called, but where it runs from, who owns it, what resources it uses?
Where does Linux store live process information that you can read without any special tools?

Data Sources
ps, top, pstree
/proc filesystem

Key Indicators
Execution path
Process owner
Resource usage
Parent process
Network activity

Suspicious Behavior
Processes in /tmp
Unknown binaries
Root-owned processes
High CPU/memory usage
Strange parent-child relationships
Unexpected network connections

Design Decisions
Use /proc/<PID>
Focus on behavior, not names
Alert on abnormal execution paths

On the network:

How do you see what ports a machine is listening on?
How do you see active connections and which process is responsible for each?
What kind of network activity would be a red flag?

Commands
ss, netstat, lsof

Data Sources
/proc/net/tcp
/proc/net/udp
/proc/net/dev

Key Indicators
Listening ports
Active connections
Process-to-network mapping

Suspicious Activity
Unknown open ports
External connections to unknown IPs
Reverse shells
High connection counts
Unusual ports
Processes in /tmp using network

Design Decisions
Use ss for simplicity
Correlate network + process data
Alert on unexpected exposure

On file integrity:

Which files on a Linux system are critical enough that any unexpected change should trigger an alert?
What file attributes or permissions settings are known to be dangerous if misconfigured?
How do you detect whether a file was modified recently?

On logging and alerting:

Where do Linux systems store their logs by default? What does each log file record?
What format do professional security tools use for structured alerts? Why does format matter?
What is the difference between a tool that floods you with alerts and one you can actually trust?
Write your findings in research.md before touching any code. Your research document will be reviewed as part of the deliverables.