# cve_query_module
These 2 python files are the NVD and OSV query module for a larger project. 

They read from "system_info.json", which has an entry for each application, operating system, and hardware identified on a system. 
Each entry in the file has a software name, version, and then the item in CPE format (see "system_info.json"). 
This is required since OSV queries by software name while NVD queries by using the CPE format.

#Example Runs

$ python3 query_nvd.py


                ╔═══════════════════════════════════╗
                ║                                   ║
                ║  BEGINNING NIST NVD QUERY MODULE  ║
                ║                                   ║
                ╚═══════════════════════════════════╝


Found 9 installed packages. Querying NVD...


Checking ubuntu 16.04 against NVD

Vulnerabilities Identified: 18

1. CVE ID: CVE-2017-9525
Severity: MEDIUM
Score: 6.7
Description: In the cron package through 3.0pl1-128 on Debian, and through 3.0pl1-128ubuntu2 on Ubuntu, the postinst maintainer script allows for group-crontab-to-root privilege escalation via symlink attacks against unsafe usage of the chown and chmod programs.
--------------------------------------------------
2. CVE ID: CVE-2018-1000135
Severity: MEDIUM
Score: 5.0
Description: GNOME NetworkManager version 1.10.2 and earlier contains a Information Exposure (CWE-200) vulnerability in DNS resolver that can result in Private DNS queries leaked to local network's DNS servers, while on VPN. This vulnerability appears to have been fixed in Some Ubuntu 16.04 packages were fixed, but later updates removed the fix. cf. https://bugs.launchpad.net/ubuntu/+bug/1754671 an upstream fix does not appear to be available at this time.
--------------------------------------------------

$ python3 query_osv.py


                ╔══════════════════════════════╗
                ║                              ║
                ║  BEGINNING OSV QUERY MODULE  ║
                ║                              ║
                ╚══════════════════════════════╝


Found 9 installed packages. Querying OSV...


Checking ubuntu 16.04 against OSV
Trying ecosystem: Ubuntu.....

No vulnerabilities found for ubuntu 16.04 across all ecosystems.


Checking nginx 1.22 against OSV
Trying ecosystem: Debian.....
Vulnerabilities Identified: 72

1. OSV Vulnerability ID: CVE-2009-2629
Severity: UNKNOWN
Score: UNKNOWN
Description: No description available.
--------------------------------------------------
2. OSV Vulnerability ID: CVE-2009-3555
Severity: UNKNOWN
Score: UNKNOWN
Description: No description available.
--------------------------------------------------
3. OSV Vulnerability ID: CVE-2009-3896
Severity: UNKNOWN
Score: UNKNOWN
Description: No description available.
--------------------------------------------------
4. OSV Vulnerability ID: CVE-2009-3898
Severity: UNKNOWN
Score: UNKNOWN
Description: No description available.
--------------------------------------------------
5. OSV Vulnerability ID: CVE-2009-4487
Severity: UNKNOWN
Score: UNKNOWN
Description: No description available.
--------------------------------------------------
6. OSV Vulnerability ID: CVE-2011-4315
Severity: UNKNOWN
Score: UNKNOWN
Description: No description available.
--------------------------------------------------
7. OSV Vulnerability ID: CVE-2011-4968
Severity: MEDIUM
Score: 4.8
Description: No description available.
--------------------------------------------------
8. OSV Vulnerability ID: CVE-2012-1180
Severity: UNKNOWN
Score: UNKNOWN
Description: No description available.
--------------------------------------------------
9. OSV Vulnerability ID: CVE-2012-2089
Severity: UNKNOWN
Score: UNKNOWN
Description: No description available.
--------------------------------------------------
10. OSV Vulnerability ID: CVE-2012-3380
Severity: UNKNOWN
Score: UNKNOWN
Description: No description available.
--------------------------------------------------
11. OSV Vulnerability ID: CVE-2012-4929
Severity: UNKNOWN
Score: UNKNOWN
Description: No description available.
--------------------------------------------------
12. OSV Vulnerability ID: CVE-2013-0337
Severity: UNKNOWN
Score: UNKNOWN
Description: No description available.
--------------------------------------------------
13. OSV Vulnerability ID: CVE-2013-2070
Severity: UNKNOWN
Score: UNKNOWN
Description: No description available.
--------------------------------------------------
14. OSV Vulnerability ID: CVE-2013-4547
Severity: UNKNOWN
Score: UNKNOWN
Description: No description available.
--------------------------------------------------
15. OSV Vulnerability ID: CVE-2014-0133
Severity: UNKNOWN
Score: UNKNOWN
Description: No description available.
--------------------------------------------------
16. OSV Vulnerability ID: CVE-2014-3556
Severity: UNKNOWN
Score: UNKNOWN
Description: No description available.
--------------------------------------------------
17. OSV Vulnerability ID: CVE-2014-3616
Severity: UNKNOWN
Score: UNKNOWN
Description: No description available.
--------------------------------------------------
18. OSV Vulnerability ID: CVE-2016-0742
Severity: HIGH
Score: 7.5
Description: No description available.
--------------------------------------------------
19. OSV Vulnerability ID: CVE-2016-0746
Severity: CRITICAL
Score: 9.8
Description: No description available.
--------------------------------------------------
