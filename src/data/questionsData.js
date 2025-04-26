const questionsData = [
  // Application Control
  {
    id: "ac_l1_q1",
    strategy: "Application Control",
    level: 1,
    text: "Application control is implemented on workstations.",
    info: "Implement application allowlisting solutions (like AppLocker, Windows Defender Application Control) on all workstations to prevent execution of unauthorized applications, malware, and scripts."
  },
  {
    id: "ac_l1_q2",
    strategy: "Application Control",
    level: 1,
    text: "Application control is applied to user profiles and temporary folders used by operating systems, web browsers and email clients.",
    info: "Configure application control to cover common exploit locations including %APPDATA%, %TEMP%, and browser cache directories where malicious code often attempts to execute."
  },
  {
    id: "ac_l1_q3",
    strategy: "Application Control",
    level: 1,
    text: "Application control restricts the execution of executables, software libraries, scripts, installers, compiled HTML, HTML applications and control panel applets to an organisation-approved set.",
    info: "Ensure your application control solution restricts all executable file types including .exe, .dll, .ocx, .vbs, .ps1, .cmd, .bat, .js, .msi, .hta, and .cpl files to an approved whitelist."
  },
  {
    id: "ac_l2_q1",
    strategy: "Application Control",
    level: 2,
    text: "Application control is implemented on internet-facing servers.",
    info: "Extend application control to internet-facing servers which are at higher risk of compromise. Use tools like AppLocker or Windows Defender Application Control to restrict which applications and scripts can run."
  },
  {
    id: "ac_l2_q2",
    strategy: "Application Control",
    level: 2,
    text: "Application control is applied to all locations other than user profiles and temporary folders used by operating systems, web browsers and email clients.",
    info: "Configure application control to monitor and restrict execution from all disk locations, including network drives and removable media, not just user profile and temporary directories."
  },
  {
    id: "ac_l2_q3",
    strategy: "Application Control",
    level: 2,
    text: "Microsoft's recommended application blocklist is implemented.",
    info: "Implement Microsoft's recommended application blocklist which prevents known high-risk applications with legitimate functionality that can be abused by attackers, such as PSExec, Mimikatz, and various remote access tools."
  },
  {
    id: "ac_l2_q4",
    strategy: "Application Control",
    level: 2,
    text: "Application control rulesets are validated on an annual or more frequent basis.",
    info: "Review and validate application control rules at least annually to remove outdated applications, add newly approved software, and ensure rules aren't overly permissive due to application changes or updates."
  },
  {
    id: "ac_l2_q5",
    strategy: "Application Control",
    level: 2,
    text: "Allowed and blocked application control events are centrally logged.",
    info: "Configure your application control solution to log both allowed and blocked execution attempts to a central logging server, SIEM or similar system for monitoring and alerting."
  },
  {
    id: "ac_l2_q6",
    strategy: "Application Control",
    level: 2,
    text: "Event logs are protected from unauthorised modification and deletion.",
    info: "Implement technical controls to prevent even privileged users from tampering with application control logs, such as using Windows event forwarding, immutable storage, or WORM (Write Once Read Many) configurations."
  },
  {
    id: "ac_l2_q7",
    strategy: "Application Control",
    level: 2,
    text: "Event logs from internet-facing servers are analysed in a timely manner to detect cyber security events.",
    info: "Establish automated reviews of application control logs from internet-facing servers at least daily to detect potential compromise attempts, focusing on blocked execution attempts and pattern anomalies."
  },
  {
    id: "ac_l3_q1",
    strategy: "Application Control",
    level: 3,
    text: "Application control is implemented on non-internet-facing servers.",
    info: "Extend application control to all non-internet-facing servers, creating a complete application control environment across your entire server infrastructure to prevent lateral movement by attackers."
  },
  {
    id: "ac_l3_q2",
    strategy: "Application Control",
    level: 3,
    text: "Application control restricts the execution of drivers to an organisation-approved set.",
    info: "Configure application control to verify driver signatures and restrict driver installation to an approved set, preventing malicious kernel-mode drivers that can bypass security controls."
  },
  {
    id: "ac_l3_q3",
    strategy: "Application Control",
    level: 3,
    text: "Microsoft’s vulnerable driver blocklist is implemented.",
    info: "Enable Microsoft's vulnerable driver blocklist to prevent the loading of known problematic drivers that could be exploited, including those with valid digital signatures that contain security vulnerabilities."
  },
  {
    id: "ac_l3_q4",
    strategy: "Application Control",
    level: 3,
    text: "Event logs from non-internet-facing servers are analysed in a timely manner to detect cyber security events.",
    info: "Implement automated review of application control logs from internal servers to detect insider threats and lateral movement by attackers who have already breached your perimeter."
  },
  {
    id: "ac_l3_q5",
    strategy: "Application Control",
    level: 3,
    text: "Event logs from workstations are analysed in a timely manner to detect cyber security events.",
    info: "Set up automated analysis of workstation application control logs to detect potential endpoint compromise, looking for patterns of blocked executions that might indicate malware or attack attempts."
  },
  // Patch Applications
  {
    id: "pa_l1_q1",
    strategy: "Patch Applications",
    level: 1,
    text: "An automated method of asset discovery is used at least fortnightly to support the detection of assets for subsequent vulnerability scanning activities.",
    info: "Deploy an automated asset discovery tool (e.g., Microsoft Endpoint Manager, Qualys, Tenable) that scans your network at least every two weeks to maintain an accurate inventory of all systems requiring patching."
  },
  {
    id: "pa_l1_q2",
    strategy: "Patch Applications",
    level: 1,
    text: "A vulnerability scanner with an up-to-date vulnerability database is used for vulnerability scanning activities.",
    info: "Implement a vulnerability scanner with regularly updated vulnerability definitions to accurately identify missing patches and security vulnerabilities across all applications."
  },
  {
    id: "pa_l1_q3",
    strategy: "Patch Applications",
    level: 1,
    text: "A vulnerability scanner is used at least daily to identify missing patches or updates for vulnerabilities in online services.",
    info: "Configure your vulnerability scanner to check internet-facing services (web applications, APIs, etc.) daily, as these are directly exposed to potential attackers and require immediate attention when vulnerabilities are discovered."
  },
  {
    id: "pa_l1_q4",
    strategy: "Patch Applications",
    level: 1,
    text: "A vulnerability scanner is used at least weekly to identify missing patches or updates for vulnerabilities in office productivity suites, web browsers and their extensions, email clients, PDF software, and security products.",
    info: "Schedule weekly vulnerability scans for common user applications that frequently process untrusted content (Office, browsers, PDF readers) as these are the primary attack vectors for malware and phishing."
  },
  {
    id: "pa_l1_q5",
    strategy: "Patch Applications",
    level: 1,
    text: "Patches, updates or other vendor mitigations for vulnerabilities in online services are applied within 48 hours of release when vulnerabilities are assessed as critical by vendors or when working exploits exist.",
    info: "Establish a rapid patch deployment process for internet-facing services that can deploy critical patches within 48 hours, including after-hours and weekend deployment capability for emergency situations."
  },
  {
    id: "pa_l1_q6",
    strategy: "Patch Applications",
    level: 1,
    text: "Patches, updates or other vendor mitigations for vulnerabilities in online services are applied within two weeks of release when vulnerabilities are assessed as non-critical by vendors and no working exploits exist.",
    info: "Implement a standard patch cycle for lower-risk vulnerabilities in internet-facing services, ensuring all non-critical patches are applied within a maximum of two weeks from release."
  },
  {
    id: "pa_l1_q7",
    strategy: "Patch Applications",
    level: 1,
    text: "Patches, updates or other vendor mitigations for vulnerabilities in office productivity suites, web browsers and their extensions, email clients, PDF software, and security products are applied within two weeks of release.",
    info: "Deploy patches for end-user applications within two weeks of release to minimize the window of opportunity for attackers targeting vulnerabilities in commonly used software."
  },
  {
    id: "pa_l1_q8",
    strategy: "Patch Applications",
    level: 1,
    text: "Online services that are no longer supported by vendors are removed.",
    info: "Identify and decommission all internet-facing services that have reached end-of-support, as these will no longer receive security updates and represent a permanent security risk to your organization."
  },
  {
    id: "pa_l1_q9",
    strategy: "Patch Applications",
    level: 1,
    text: "Office productivity suites, web browsers and their extensions, email clients, PDF software, Adobe Flash Player, and security products that are no longer supported by vendors are removed.",
    info: "Remove or replace all end-of-life applications from user workstations, particularly those that process untrusted content, as they contain unpatched vulnerabilities that can be exploited by attackers."
  },
  {
    id: "pa_l2_q1",
    strategy: "Patch Applications",
    level: 2,
    text: "A vulnerability scanner is used at least fortnightly to identify missing patches or updates for vulnerabilities in applications other than office productivity suites, web browsers and their extensions, email clients, PDF software, and security products.",
    info: "Extend vulnerability scanning to all other business applications (ERPs, CRMs, industry-specific software) at least every two weeks to ensure these systems are also kept current with security patches."
  },
  {
    id: "pa_l2_q2",
    strategy: "Patch Applications",
    level: 2,
    text: "Patches, updates or other vendor mitigations for vulnerabilities in applications other than office productivity suites, web browsers and their extensions, email clients, PDF software, and security products are applied within one month of release.",
    info: "Establish a monthly patch cycle for business applications and specialized software, ensuring all patches are tested and deployed within 30 days of release."
  },
  {
    id: "pa_l3_q1",
    strategy: "Patch Applications",
    level: 3,
    text: "Patches, updates or other vendor mitigations for vulnerabilities in office productivity suites, web browsers and their extensions, email clients, PDF software, and security products are applied within 48 hours of release when vulnerabilities are assessed as critical by vendors or when working exploits exist.",
    info: "Implement an emergency patching process for end-user applications that can deploy critical patches within 48 hours when high-risk vulnerabilities are identified, particularly those with known exploits in the wild."
  },
  {
    id: "pa_l3_q2",
    strategy: "Patch Applications",
    level: 3,
    text: "Patches, updates or other vendor mitigations for vulnerabilities in office productivity suites, web browsers and their extensions, email clients, PDF software, and security products are applied within two weeks of release when vulnerabilities are assessed as non-critical by vendors and no working exploits exist.",
    info: "Maintain a two-week patch cycle for non-critical updates to end-user applications, ensuring all systems receive these updates through automated deployment mechanisms."
  },
  {
    id: "pa_l3_q3",
    strategy: "Patch Applications",
    level: 3,
    text: "Applications other than office productivity suites, web browsers and their extensions, email clients, PDF software, Adobe Flash Player, and security products that are no longer supported by vendors are removed.",
    info: "Create and maintain an application lifecycle inventory to identify and remove all end-of-life applications across your entire software portfolio, including business-specific and internal applications."
  },
  // Patch Operating Systems
  {
    id: "pos_l1_q1",
    strategy: "Patch Operating Systems",
    level: 1,
    text: "An automated method of asset discovery is used at least fortnightly to support the detection of assets for subsequent vulnerability scanning activities.",
    info: "Deploy network discovery tools that run at least every two weeks to identify all devices, including unauthorized ones, ensuring no systems are missed in your operating system patching program."
  },
  {
    id: "pos_l1_q2",
    strategy: "Patch Operating Systems",
    level: 1,
    text: "A vulnerability scanner with an up-to-date vulnerability database is used for vulnerability scanning activities.",
    info: "Implement a vulnerability management solution with current OS vulnerability definitions that can accurately identify missing operating system patches across your environment."
  },
  {
    id: "pos_l1_q3",
    strategy: "Patch Operating Systems",
    level: 1,
    text: "A vulnerability scanner is used at least daily to identify missing patches or updates for vulnerabilities in operating systems of internet-facing servers and internet-facing network devices.",
    info: "Configure your vulnerability scanner to check internet-facing server OS and network device patches daily, as these are directly exposed to attackers and require immediate attention when vulnerabilities are found."
  },
  {
    id: "pos_l1_q4",
    strategy: "Patch Operating Systems",
    level: 1,
    text: "A vulnerability scanner is used at least fortnightly to identify missing patches or updates for vulnerabilities in operating systems of workstations, non-internet-facing servers and non-internet-facing network devices.",
    info: "Schedule bi-weekly vulnerability scans for internal systems including workstations, internal servers, and network devices to identify missing OS patches that could be exploited in lateral movement."
  },
  {
    id: "pos_l1_q5",
    strategy: "Patch Operating Systems",
    level: 1,
    text: "Patches, updates or other vendor mitigations for vulnerabilities in operating systems of internet-facing servers and internet-facing network devices are applied within 48 hours of release when vulnerabilities are assessed as critical by vendors or when working exploits exist.",
    info: "Establish a rapid patch deployment process for internet-facing systems that can deploy critical OS patches within 48 hours, including emergency deployment capabilities for zero-day vulnerabilities."
  },
  {
    id: "pos_l1_q6",
    strategy: "Patch Operating Systems",
    level: 1,
    text: "Patches, updates or other vendor mitigations for vulnerabilities in operating systems of internet-facing servers and internet-facing network devices are applied within two weeks of release when vulnerabilities are assessed as non-critical by vendors and no working exploits exist.",
    info: "Implement a standard patch cycle for internet-facing systems, ensuring all non-critical OS patches are applied within a maximum of two weeks from release after appropriate testing."
  },
  {
    id: "pos_l1_q7",
    strategy: "Patch Operating Systems",
    level: 1,
    text: "Patches, updates or other vendor mitigations for vulnerabilities in operating systems of workstations, non-internet-facing servers and non-internet-facing network devices are applied within one month of release.",
    info: "Establish a monthly patching process for internal systems, with automated deployment tools that ensure all workstations and internal servers receive OS updates within 30 days."
  },
  {
    id: "pos_l1_q8",
    strategy: "Patch Operating Systems",
    level: 1,
    text: "Operating systems that are no longer supported by vendors are replaced.",
    info: "Identify and replace all operating systems that have reached end-of-life (like Windows 7, Server 2008), as these no longer receive security updates and represent significant security risks."
  },
  {
    id: "pos_l2_q1",
    strategy: "Patch Operating Systems",
    level: 2,
    text: "Event logs are protected from unauthorised modification and deletion.",
    info: "Configure operating system event logs to be immutable, such as using Windows event forwarding to a hardened collector or sending logs to a dedicated SIEM with tamper-proof storage."
  },
  {
    id: "pos_l2_q2",
    strategy: "Patch Operating Systems",
    level: 2,
    text: "Event logs from internet-facing servers are analysed in a timely manner to detect cyber security events.",
    info: "Implement automated log analysis for internet-facing servers with alerts for suspicious activities like failed login attempts, privilege escalation, or unusual process execution that might indicate compromise."
  },
  {
    id: "pos_l3_q1",
    strategy: "Patch Operating Systems",
    level: 3,
    text: "A vulnerability scanner is used at least fortnightly to identify missing patches or updates for vulnerabilities in drivers.",
    info: "Extend vulnerability scanning to include hardware drivers, particularly those affecting security features like network adapters, storage controllers, and graphics drivers which can be exploited for privilege escalation."
  },
  {
    id: "pos_l3_q2",
    strategy: "Patch Operating Systems",
    level: 3,
    text: "A vulnerability scanner is used at least fortnightly to identify missing patches or updates for vulnerabilities in firmware.",
    info: "Implement firmware vulnerability scanning for all hardware components (BIOS/UEFI, network equipment, storage systems) bi-weekly to identify outdated firmware that could contain security vulnerabilities."
  },
  {
    id: "pos_l3_q3",
    strategy: "Patch Operating Systems",
    level: 3,
    text: "Patches, updates or other vendor mitigations for vulnerabilities in operating systems of workstations, non-internet-facing servers and non-internet-facing network devices are applied within 48 hours of release when vulnerabilities are assessed as critical by vendors or when working exploits exist.",
    info: "Accelerate internal system patching for critical vulnerabilities to within 48 hours, focusing on Common Vulnerabilities and Exposures (CVEs) rated as critical or those with known active exploitation."
  },
  {
    id: "pos_l3_q4",
    strategy: "Patch Operating Systems",
    level: 3,
    text: "Patches, updates or other vendor mitigations for vulnerabilities in operating systems of workstations, non-internet-facing servers and non-internet-facing network devices are applied within one month of release when vulnerabilities are assessed as non-critical by vendors and no working exploits exist.",
    info: "Maintain a monthly patch cycle for non-critical OS updates to internal systems with testing and verification procedures to prevent disruption to business operations."
  },
  {
    id: "pos_l3_q5",
    strategy: "Patch Operating Systems",
    level: 3,
    text: "Patches, updates or other vendor mitigations for vulnerabilities in drivers are applied within 48 hours of release when vulnerabilities are assessed as critical by vendors or when working exploits exist.",
    info: "Implement an emergency process for deploying critical driver updates within 48 hours, particularly for drivers that can be exploited for privilege escalation attacks."
  },
  {
    id: "pos_l3_q6",
    strategy: "Patch Operating Systems",
    level: 3,
    text: "Patches, updates or other vendor mitigations for vulnerabilities in drivers are applied within one month of release when vulnerabilities are assessed as non-critical by vendors and no working exploits exist.",
    info: "Establish a monthly patch cycle for non-critical driver updates across all systems, with appropriate testing to prevent compatibility issues."
  },
  {
    id: "pos_l3_q7",
    strategy: "Patch Operating Systems",
    level: 3,
    text: "Patches, updates or other vendor mitigations for vulnerabilities in firmware are applied within 48 hours of release when vulnerabilities are assessed as critical by vendors or when working exploits exist.",
    info: "Create a rapid response process for critical firmware vulnerabilities, ensuring updates can be tested and deployed within 48 hours for security issues that could affect the system before the OS loads."
  },
  {
    id: "pos_l3_q8",
    strategy: "Patch Operating Systems",
    level: 3,
    text: "Patches, updates or other vendor mitigations for vulnerabilities in firmware are applied within one month of release when vulnerabilities are assessed as non-critical by vendors and no working exploits exist.",
    info: "Include firmware in your monthly patch cycle, ensuring all non-critical firmware updates are applied within 30 days across BIOS/UEFI, network equipment, and other infrastructure components."
  },
  {
    id: "pos_l3_q9",
    strategy: "Patch Operating Systems",
    level: 3,
    text: "The latest release, or the previous release, of operating systems are used.",
    info: "Establish an OS lifecycle management policy that ensures all systems run either the current or immediately previous OS version (n or n-1), with regular upgrades to maintain this standard."
  },
  {
    id: "pos_l3_q10",
    strategy: "Patch Operating Systems",
    level: 3,
    text: "Event logs from non-internet-facing servers are analysed in a timely manner to detect cyber security events.",
    info: "Implement automated log analysis for internal servers to detect lateral movement, privilege escalation, or suspicious account activities that could indicate compromise after initial penetration."
  },
  {
    id: "pos_l3_q11",
    strategy: "Patch Operating Systems",
    level: 3,
    text: "Event logs from workstations are analysed in a timely manner to detect cyber security events.",
    info: "Set up a SIEM or similar solution to collect and analyze workstation logs, with alerts for suspicious behavior like unusual PowerShell commands, unexpected application installations, or credential access attempts."
  },
  // Multi-factor Authentication
  {
    id: "mfa_l1_q1",
    strategy: "Multi-factor Authentication",
    level: 1,
    text: "Multi-factor authentication is used to authenticate users to their organisation's online services that process, store or communicate their organisation's sensitive data.",
    info: "Implement MFA for all internal web applications, portals, and cloud services that contain sensitive organizational data such as HR systems, financial applications, and document management systems."
  },
  {
    id: "mfa_l1_q2",
    strategy: "Multi-factor Authentication",
    level: 1,
    text: "Multi-factor authentication is used to authenticate users to third-party online services that process, store or communicate their organisation's sensitive data.",
    info: "Ensure MFA is enabled on all third-party SaaS applications that handle sensitive data, including CRM systems, cloud storage, email providers, and specialized business applications."
  },
  {
    id: "mfa_l1_q3",
    strategy: "Multi-factor Authentication",
    level: 1,
    text: "Multi-factor authentication (where available) is used to authenticate users to third-party online services that process, store or communicate their organisation's non-sensitive data.",
    info: "Extend MFA to all third-party services even for non-sensitive data where the feature is available, as these accounts could be leveraged for further attacks if compromised."
  },
  {
    id: "mfa_l1_q4",
    strategy: "Multi-factor Authentication",
    level: 1,
    text: "Multi-factor authentication is used to authenticate users to their organisation's online customer services that process, store or communicate their organisation's sensitive customer data.",
    info: "Deploy MFA for staff accessing customer-facing systems or customer data repositories to prevent unauthorized access to customer information, protecting against both external attacks and insider threats."
  },
  {
    id: "mfa_l1_q5",
    strategy: "Multi-factor Authentication",
    level: 1,
    text: "Multi-factor authentication is used to authenticate users to third-party online customer services that process, store or communicate their organisation's sensitive customer data.",
    info: "Enable MFA for all staff accounts on third-party customer relationship management systems, support platforms, and other customer data services to protect customer information."
  },
  {
    id: "mfa_l1_q6",
    strategy: "Multi-factor Authentication",
    level: 1,
    text: "Multi-factor authentication is used to authenticate customers to online customer services that process, store or communicate sensitive customer data.",
    info: "Offer and encourage MFA for customer accounts that access your online services containing sensitive data like personal information, payment details, or account management features."
  },
  {
    id: "mfa_l1_q7",
    strategy: "Multi-factor Authentication",
    level: 1,
    text: "Multi-factor authentication uses either: something users have and something users know, or something users have that is unlocked by something users know or are.",
    info: "Implement MFA using secure methods such as hardware tokens plus passwords, authenticator apps plus PINs, or biometric-protected security keys, avoiding less secure options like SMS-based verification."
  },
  {
    id: "mfa_l2_q1",
    strategy: "Multi-factor Authentication",
    level: 2,
    text: "Multi-factor authentication is used to authenticate privileged users of systems.",
    info: "Require MFA for all privileged account access including administrator accounts, service accounts with elevated permissions, and domain admin credentials, as these accounts are primary targets for attackers."
  },
  {
    id: "mfa_l2_q2",
    strategy: "Multi-factor Authentication",
    level: 2,
    text: "Multi-factor authentication is used to authenticate unprivileged users of systems.",
    info: "Extend MFA to all standard user accounts for system access, including workstation logins, VPN connections, and remote desktop services to prevent credential-based attacks."
  },
  {
    id: "mfa_l2_q3",
    strategy: "Multi-factor Authentication",
    level: 2,
    text: "Multi-factor authentication used for authenticating users of online services is phishing-resistant.",
    info: "Implement phishing-resistant MFA methods such as FIDO2/WebAuthn security keys, PKI smart cards, or push notifications with number matching for online services to defend against sophisticated phishing attacks."
  },
  {
    id: "mfa_l2_q4",
    strategy: "Multi-factor Authentication",
    level: 2,
    text: "Multi-factor authentication used for authenticating customers of online customer services provides a phishing-resistant option.",
    info: "Offer customers the option to use phishing-resistant authentication methods like FIDO2 security keys or WebAuthn biometrics, particularly for high-value accounts or transactions."
  },
  {
    id: "mfa_l2_q5",
    strategy: "Multi-factor Authentication",
    level: 2,
    text: "Multi-factor authentication used for authenticating users of systems is phishing-resistant.",
    info: "Deploy phishing-resistant MFA for system access using hardware tokens, smart cards, or Windows Hello for Business rather than methods vulnerable to phishing like one-time codes."
  },
  {
    id: "mfa_l2_q6",
    strategy: "Multi-factor Authentication",
    level: 2,
    text: "Successful and unsuccessful multi-factor authentication events are centrally logged.",
    info: "Configure all MFA systems to send authentication logs to a central SIEM or log management solution, including both successful and failed attempts, to detect potential brute force or timing attacks."
  },
  {
    id: "mfa_l2_q7",
    strategy: "Multi-factor Authentication",
    level: 2,
    text: "Event logs are protected from unauthorised modification and deletion.",
    info: "Implement technical controls to prevent tampering with MFA logs, such as using write-once storage, log forwarding to secured servers, or cloud-based immutable logging services."
  },
  {
    id: "mfa_l2_q8",
    strategy: "Multi-factor Authentication",
    level: 2,
    text: "Event logs from internet-facing servers are analysed in a timely manner to detect cyber security events.",
    info: "Set up automated analysis of MFA logs from internet-facing systems with alerts for suspicious patterns like multiple failed attempts, successful logins from unusual locations, or authentication attempts at unusual times."
  },
  {
    id: "mfa_l3_q1",
    strategy: "Multi-factor Authentication",
    level: 3,
    text: "Multi-factor authentication is used to authenticate users of data repositories.",
    info: "Implement MFA for access to all data repositories including databases, file shares, document management systems, and backup systems, even for internal network access."
  },
  {
    id: "mfa_l3_q2",
    strategy: "Multi-factor Authentication",
    level: 3,
    text: "Multi-factor authentication used for authenticating customers of online customer services is phishing-resistant.",
    info: "Require (not just offer) phishing-resistant MFA for all customer authentication to sensitive services, such as FIDO2 security keys, platform authenticators, or biometric verification with secure device binding."
  },
  {
    id: "mfa_l3_q3",
    strategy: "Multi-factor Authentication",
    level: 3,
    text: "Multi-factor authentication used for authenticating users of data repositories is phishing-resistant.",
    info: "Use only phishing-resistant MFA methods for data repository access, implementing certificate-based authentication, hardware tokens, or Windows Hello for Business rather than time-based OTP codes."
  },
  {
    id: "mfa_l3_q4",
    strategy: "Multi-factor Authentication",
    level: 3,
    text: "Event logs from non-internet-facing servers are analysed in a timely manner to detect cyber security events.",
    info: "Extend automated MFA log analysis to include internal servers and systems, implementing correlation rules to detect potential lateral movement or privilege escalation attempts."
  },
  {
    id: "mfa_l3_q5",
    strategy: "Multi-factor Authentication",
    level: 3,
    text: "Event logs from workstations are analysed in a timely manner to detect cyber security events.",
    info: "Collect and analyze MFA logs from workstations to detect unauthorized access attempts, focusing on failed MFA challenges that might indicate stolen credentials being tested."
  },
  // Restrict Admin Privileges
  {
    id: "rap_l1_q1",
    strategy: "Restrict Admin Privileges",
    level: 1,
    text: "Requests for privileged access to systems, applications and data repositories are validated when first requested.",
    info: "Implement a formal approval process for all privileged access requests that validates business need, appropriate authorization, and minimum required privileges before granting admin access."
  },
  {
    id: "rap_l1_q2",
    strategy: "Restrict Admin Privileges",
    level: 1,
    text: "Privileged users are assigned a dedicated privileged user account to be used solely for duties requiring privileged access.",
    info: "Provide administrators with separate accounts: one standard account for daily work and email, and a dedicated admin account only used when performing administrative tasks."
  },
  {
    id: "rap_l1_q3",
    strategy: "Restrict Admin Privileges",
    level: 1,
    text: "Privileged user accounts (excluding those explicitly authorised to access online services) are prevented from accessing the internet, email and web services.",
    info: "Configure technical controls to block privileged accounts from accessing the internet, email, or web services, reducing the risk of these accounts being compromised through phishing or malicious websites."
  },
  {
    id: "rap_l1_q4",
    strategy: "Restrict Admin Privileges",
    level: 1,
    text: "Privileged user accounts explicitly authorised to access online services are strictly limited to only what is required for users and services to undertake their duties.",
    info: "For admin accounts that must access online services (e.g., cloud administrators), implement web filtering to restrict access to only the specific management consoles or services needed for their role."
  },
  {
    id: "rap_l1_q5",
    strategy: "Restrict Admin Privileges",
    level: 1,
    text: "Privileged users use separate privileged and unprivileged operating environments.",
    info: "Provide dedicated, hardened workstations or VMs for administrative tasks that are separate from regular workstations used for email and general work activities."
  },
  {
    id: "rap_l1_q6",
    strategy: "Restrict Admin Privileges",
    level: 1,
    text: "Unprivileged user accounts cannot logon to privileged operating environments.",
    info: "Configure access controls to prevent standard user accounts from logging into admin workstations, jump servers, or administrative virtual machines to maintain a secure administrative boundary."
  },
  {
    id: "rap_l1_q7",
    strategy: "Restrict Admin Privileges",
    level: 1,
    text: "Privileged user accounts (excluding local administrator accounts) cannot logon to unprivileged operating environments.",
    info: "Prevent domain admin accounts and other high-privilege accounts from logging into standard workstations where they could be exposed to malware or credential theft attacks like pass-the-hash."
  },
  {
    id: "rap_l2_q1",
    strategy: "Restrict Admin Privileges",
    level: 2,
    text: "Privileged access to systems, applications and data repositories is disabled after 12 months unless revalidated.",
    info: "Implement a privileged access review process that automatically revokes admin accounts if not recertified annually, ensuring all privileges have ongoing business justification."
  },
  {
    id: "rap_l2_q2",
    strategy: "Restrict Admin Privileges",
    level: 2,
    text: "Privileged access to systems and applications is disabled after 45 days of inactivity.",
    info: "Configure automated monitoring to detect and disable privileged accounts that haven't been used for 45 days, reducing the attack surface from orphaned or unnecessary admin accounts."
  },
  {
    id: "rap_l2_q3",
    strategy: "Restrict Admin Privileges",
    level: 2,
    text: "Privileged operating environments are not virtualised within unprivileged operating environments.",
    info: "Avoid nesting administrative environments (VMs or containers) within standard user workstations where the host could be compromised, potentially affecting the security of the admin environment."
  },
  {
    id: "rap_l2_q4",
    strategy: "Restrict Admin Privileges",
    level: 2,
    text: "Administrative activities are conducted through jump servers.",
    info: "Implement secure jump servers (bastion hosts) for administrative access to servers and infrastructure, providing a controlled, monitored, and hardened path for all administrative activities."
  },
  {
    id: "rap_l2_q5",
    strategy: "Restrict Admin Privileges",
    level: 2,
    text: "Credentials for break glass accounts, local administrator accounts and service accounts are long, unique, unpredictable and managed.",
    info: "Use a Privileged Access Management (PAM) system to generate, store, and rotate complex passwords (20+ characters) for emergency accounts, local admin accounts, and service accounts."
  },
  {
    id: "rap_l2_q6",
    strategy: "Restrict Admin Privileges",
    level: 2,
    text: "Privileged access events are centrally logged.",
    info: "Configure all systems to forward privileged account activities (logons, command execution, permission changes) to a central SIEM or log management system for monitoring and forensic purposes."
  },
  {
    id: "rap_l2_q7",
    strategy: "Restrict Admin Privileges",
    level: 2,
    text: "Privileged user account and security group management events are centrally logged.",
    info: "Log all changes to privileged access rights, including group membership changes, account creations, permission grants, and role assignments to detect unauthorized privilege escalation."
  },
  {
    id: "rap_l2_q8",
    strategy: "Restrict Admin Privileges",
    level: 2,
    text: "Event logs are protected from unauthorised modification and deletion.",
    info: "Implement technical safeguards to prevent even privileged users from tampering with admin activity logs, such as using write-once storage, WORM technology, or forwarding to secured logging servers."
  },
  {
    id: "rap_l2_q9",
    strategy: "Restrict Admin Privileges",
    level: 2,
    text: "Event logs from internet-facing servers are analysed in a timely manner to detect cyber security events.",
    info: "Set up automated analysis of privileged access logs from internet-facing systems with alerts for suspicious administrative activities, particularly outside business hours or from unusual locations."
  },
  {
    id: "rap_l3_q1",
    strategy: "Restrict Admin Privileges",
    level: 3,
    text: "Privileged access to systems, applications and data repositories is limited to only what is required for users and services to undertake their duties.",
    info: "Implement granular privilege management with role-based access control and just-enough-admin principles, ensuring admins have only the specific permissions needed for their tasks."
  },
  {
    id: "rap_l3_q2",
    strategy: "Restrict Admin Privileges",
    level: 3,
    text: "Secure Admin Workstations are used in the performance of administrative activities.",
    info: "Deploy hardened, dedicated Privileged Access Workstations (PAWs) for administrative tasks with enhanced security controls like application whitelisting, UEFI SecureBoot, and disabled internet access."
  },
  {
    id: "rap_l3_q3",
    strategy: "Restrict Admin Privileges",
    level: 3,
    text: "Just-in-time administration is used for administering systems and applications.",
    info: "Implement temporary privilege elevation using a just-in-time model where admin rights are granted only when needed, for a limited time period, and with appropriate approvals."
  },
  {
    id: "rap_l3_q4",
    strategy: "Restrict Admin Privileges",
    level: 3,
    text: "Memory integrity functionality is enabled.",
    info: "Enable Windows memory integrity features (Hypervisor-Protected Code Integrity) on admin workstations to prevent the injection of malicious code into high-security processes."
  },
  {
    id: "rap_l3_q5",
    strategy: "Restrict Admin Privileges",
    level: 3,
    text: "Local Security Authority protection functionality is enabled.",
    info: "Enable LSA protection features on all systems to prevent credential theft techniques that attempt to extract authentication information from memory."
  },
  {
    id: "rap_l3_q6",
    strategy: "Restrict Admin Privileges",
    level: 3,
    text: "Credential Guard functionality is enabled.",
    info: "Deploy Windows Credential Guard on all compatible systems to use virtualization-based security to isolate credential storage, protecting against advanced credential theft techniques."
  },
  {
    id: "rap_l3_q7",
    strategy: "Restrict Admin Privileges",
    level: 3,
    text: "Remote Credential Guard functionality is enabled.",
    info: "Enable Remote Credential Guard for RDP connections to prevent credentials from being exposed on remote servers during administrative remote sessions."
  },
  {
    id: "rap_l3_q8",
    strategy: "Restrict Admin Privileges",
    level: 3,
    text: "Event logs from non-internet-facing servers are analysed in a timely manner to detect cyber security events.",
    info: "Extend privileged account monitoring to internal servers with automated analysis to detect lateral movement, privilege escalation, or unauthorized administrative actions."
  },
  {
    id: "rap_l3_q9",
    strategy: "Restrict Admin Privileges",
    level: 3,
    text: "Event logs from workstations are analysed in a timely manner to detect cyber security events.",
    info: "Implement monitoring of admin activity on workstations to detect potential misuse of privileges or compromised admin accounts attempting to access sensitive data."
  },
  // Configure MS Office Macros
  {
    id: "cm_l1_q1",
    strategy: "Configure MS Office Macros",
    level: 1,
    text: "Microsoft Office macros are disabled for users that do not have a demonstrated business requirement.",
    info: "Disable Office macros by default for all users, and only enable them for specific individuals or departments with documented business requirements through Group Policy or other management tools."
  },
  {
    id: "cm_l1_q2",
    strategy: "Configure MS Office Macros",
    level: 1,
    text: "Microsoft Office macros in files originating from the internet are blocked.",
    info: "Configure Office applications to block all macros in documents downloaded from the internet, email attachments, or other external sources, regardless of macro security settings."
  },
  {
    id: "cm_l1_q3",
    strategy: "Configure MS Office Macros",
    level: 1,
    text: "Microsoft Office macro antivirus scanning is enabled.",
    info: "Ensure antivirus solutions are configured to scan the content of Office files and any macros they contain before execution, to detect malicious code embedded in macros."
  },
  {
    id: "cm_l1_q4",
    strategy: "Configure MS Office Macros",
    level: 1,
    text: "Microsoft Office macro security settings cannot be changed by users.",
    info: "Use Group Policy or Microsoft Endpoint Manager to lock down macro security settings so regular users cannot modify them, preventing users from bypassing macro security controls."
  },
  {
    id: "cm_l2_q1",
    strategy: "Configure MS Office Macros",
    level: 2,
    text: "Microsoft Office macros are blocked from making Win32 API calls.",
    info: "Enable the Office security setting that blocks macros from accessing Win32 APIs, which are commonly used in advanced macro-based attacks to execute malicious code outside the Office sandbox."
  },
  {
    id: "cm_l3_q1",
    strategy: "Configure MS Office Macros",
    level: 3,
    text: "Only Microsoft Office macros running from within a sandboxed environment, a Trusted Location or that are digitally signed by a trusted publisher are allowed to execute.",
    info: "Configure Office to only allow macros from trusted locations (controlled file shares) or those with approved digital signatures, blocking all other macro execution regardless of content."
  },
  {
    id: "cm_l3_q2",
    strategy: "Configure MS Office Macros",
    level: 3,
    text: "Microsoft Office macros are checked to ensure they are free of malicious code before being digitally signed or placed within Trusted Locations.",
    info: "Implement a formal code review process for all macros before they are approved, signed, and deployed to verify they don't contain malicious functionality or security vulnerabilities."
  },
  {
    id: "cm_l3_q3",
    strategy: "Configure MS Office Macros",
    level: 3,
    text: "Only privileged users responsible for checking that Microsoft Office macros are free of malicious code can write to and modify content within Trusted Locations.",
    info: "Restrict write permissions to trusted macro locations (file shares or repositories) to only authorized security personnel who verify macro code, preventing unauthorized additions."
  },
  {
    id: "cm_l3_q4",
    strategy: "Configure MS Office Macros",
    level: 3,
    text: "Microsoft Office macros digitally signed by an untrusted publisher cannot be enabled via the Message Bar or Backstage View.",
    info: "Configure Office to prevent users from manually enabling macros signed by publishers not in the trusted publishers list, removing the option to override security warnings."
  },
  {
    id: "cm_l3_q5",
    strategy: "Configure MS Office Macros",
    level: 3,
    text: "Microsoft Office macros digitally signed by signatures other than V3 signatures cannot be enabled via the Message Bar or Backstage View.",
    info: "Configure Office to only accept the most secure signature type (V3 signatures) for macros, rejecting older and less secure signature formats that may be vulnerable to exploitation."
  },
  {
    id: "cm_l3_q6",
    strategy: "Configure MS Office Macros",
    level: 3,
    text: "Microsoft Office's list of trusted publishers is validated on an annual or more frequent basis.",
    info: "Establish a process to review and verify all trusted publishers in Office at least annually, removing publishers that are no longer used and validating the continued security of retained certificates."
  },
  // User Application Hardening
  {
    id: "uah_l1_q1",
    strategy: "User Application Hardening",
    level: 1,
    text: "Internet Explorer 11 is disabled or removed.",
    info: "Disable or completely remove Internet Explorer 11 using Group Policy or Windows Features, as it contains numerous legacy vulnerabilities and is no longer receiving security updates."
  },
  {
    id: "uah_l1_q2",
    strategy: "User Application Hardening",
    level: 1,
    text: "Web browsers do not process Java from the internet.",
    info: "Disable Java plugins in all browsers or use Group Policy to prevent Java execution from internet sites, as Java browser plugins are a common attack vector for drive-by downloads."
  },
  {
    id: "uah_l1_q3",
    strategy: "User Application Hardening",
    level: 1,
    text: "Web browsers do not process web advertisements from the internet.",
    info: "Implement ad-blocking technology at the browser level or through web proxies to prevent malvertising attacks where attackers use legitimate ad networks to deliver malware."
  },
  {
    id: "uah_l1_q4",
    strategy: "User Application Hardening",
    level: 1,
    text: "Web browser security settings cannot be changed by users.",
    info: "Lock down browser security settings through Group Policy or endpoint management tools so users cannot disable security features like SmartScreen Filter, phishing protection, or popup blocking."
  },
  {
    id: "uah_l2_q1",
    strategy: "User Application Hardening",
    level: 2,
    text: "Web browsers are hardened using ASD and vendor hardening guidance, with the most restrictive guidance taking precedence when conflicts occur.",
    info: "Apply comprehensive browser hardening guidelines from ACSC and browser vendors (Microsoft, Google, Mozilla) to configure advanced security settings like TLS requirements, certificate handling, and content restrictions."
  },
  {
    id: "uah_l2_q2",
    strategy: "User Application Hardening",
    level: 2,
    text: "Microsoft Office is blocked from creating child processes.",
    info: "Enable the Attack Surface Reduction rule that prevents Office applications from creating child processes, a common technique used in macro-based attacks to launch malware."
  },
  {
    id: "uah_l2_q3",
    strategy: "User Application Hardening",
    level: 2,
    text: "Microsoft Office is blocked from creating executable content.",
    info: "Implement Attack Surface Reduction rules to prevent Office applications from generating executable files, which attackers use to drop second-stage payloads onto systems."
  },
  {
    id: "uah_l2_q4",
    strategy: "User Application Hardening",
    level: 2,
    text: "Microsoft Office is blocked from injecting code into other processes.",
    info: "Enable protections that prevent Office applications from injecting code into other processes, a technique commonly used to evade detection and maintain persistence."
  },
  {
    id: "uah_l2_q5",
    strategy: "User Application Hardening",
    level: 2,
    text: "Microsoft Office is configured to prevent activation of Object Linking and Embedding packages.",
    info: "Disable Office OLE package activation to prevent attacks that use embedded objects to execute malicious code when documents are opened, a common technique in spear-phishing campaigns."
  },
  {
    id: "uah_l2_q6",
    strategy: "User Application Hardening",
    level: 2,
    text: "Office productivity suites are hardened using ASD and vendor hardening guidance, with the most restrictive guidance taking precedence when conflicts occur.",
    info: "Apply comprehensive Office suite hardening based on ACSC and Microsoft guidance, including disabling automated DDE functionality, ActiveX controls, and other potentially dangerous features."
  },
  {
    id: "uah_l2_q7",
    strategy: "User Application Hardening",
    level: 2,
    text: "Office productivity suite security settings cannot be changed by users.",
    info: "Use Group Policy or Endpoint Management tools to lock down Office security settings so users cannot modify or disable protections like Protected View, Data Execution Prevention, or macro settings."
  },
  {
    id: "uah_l2_q8",
    strategy: "User Application Hardening",
    level: 2,
    text: "PDF software is blocked from creating child processes.",
    info: "Configure security settings in PDF software to prevent it from launching other applications or processes, a technique used in PDF-based attacks to execute malware."
  },
  {
    id: "uah_l2_q9",
    strategy: "User Application Hardening",
    level: 2,
    text: "PDF software is hardened using ASD and vendor hardening guidance, with the most restrictive guidance taking precedence when conflicts occur.",
    info: "Implement security configurations for PDF readers based on ACSC and vendor guidance, including disabling JavaScript, external content loading, and embedded executables."
  },
  {
    id: "uah_l2_q10",
    strategy: "User Application Hardening",
    level: 2,
    text: "PDF software security settings cannot be changed by users.",
    info: "Lock down security settings in PDF readers through Group Policy or management tools so users cannot enable dangerous features like executing embedded JavaScript or launching external applications."
  },
  {
    id: "uah_l2_q11",
    strategy: "User Application Hardening",
    level: 2,
    text: "PowerShell module logging, script block logging and transcription events are centrally logged.",
    info: "Enable comprehensive PowerShell logging including module loading, script block execution, and full command transcription, all forwarded to a central logging system for threat detection."
  },
  {
    id: "uah_l2_q12",
    strategy: "User Application Hardening",
    level: 2,
    text: "Command line process creation events are centrally logged.",
    info: "Configure Windows to log all command line arguments used when creating processes, capturing the full command executed, not just the program name, to detect malicious command line activity."
  },
  {
    id: "uah_l2_q13",
    strategy: "User Application Hardening",
    level: 2,
    text: "Event logs are protected from unauthorised modification and deletion.",
    info: "Implement technical controls to prevent tampering with application and security logs, such as using Windows event forwarding to secure log collectors or SIEM solutions with tamper-proof storage."
  },
  {
    id: "uah_l2_q14",
    strategy: "User Application Hardening",
    level: 2,
    text: "Event logs from internet-facing servers are analysed in a timely manner to detect cyber security events.",
    info: "Set up automated analysis of application logs from internet-facing systems with alerts for suspicious activities like unexpected application behavior, crashes, or exploit attempts."
  },
  {
    id: "uah_l3_q1",
    strategy: "User Application Hardening",
    level: 3,
    text: ".NET Framework 3.5 (includes .NET 2.0 and 3.0) is disabled or removed.",
    info: "Remove or disable legacy .NET Framework versions (3.5 and earlier) that contain known vulnerabilities and are commonly targeted by attackers for exploitation if not required by business applications."
  },
  {
    id: "uah_l3_q2",
    strategy: "User Application Hardening",
    level: 3,
    text: "Windows PowerShell 2.0 is disabled or removed.",
    info: "Disable PowerShell version 2.0, which lacks modern security features like script block logging and AMSI integration, making it a target for attackers seeking to evade security controls."
  },
  {
    id: "uah_l3_q3",
    strategy: "User Application Hardening",
    level: 3,
    text: "PowerShell is configured to use Constrained Language Mode.",
    info: "Implement PowerShell Constrained Language Mode via AppLocker or Device Guard to restrict PowerShell to a limited subset of functionality, preventing many common PowerShell-based attack techniques."
  },
  {
    id: "uah_l3_q4",
    strategy: "User Application Hardening",
    level: 3,
    text: "Event logs from non-internet-facing servers are analysed in a timely manner to detect cyber security events.",
    info: "Extend application log monitoring to internal servers with automated analysis to detect anomalous behavior that might indicate lateral movement or privilege escalation attempts."
  },
  {
    id: "uah_l3_q5",
    strategy: "User Application Hardening",
    level: 3,
    text: "Event logs from workstations are analysed in a timely manner to detect cyber security events.",
    info: "Implement monitoring of application logs from workstations to detect suspicious application behavior or execution patterns that might indicate compromise, particularly focusing on PowerShell and command-line activity."
  },
  // Regular Backups
  {
    id: "rb_l1_q1",
    strategy: "Regular Backups",
    level: 1,
    text: "Backups of data, applications and settings are performed and retained in accordance with business criticality and business continuity requirements.",
    info: "Implement a tiered backup strategy based on data criticality, with appropriate frequency (daily/hourly) and retention periods (days/weeks/months/years) aligned with your recovery objectives."
  },
  {
    id: "rb_l1_q2",
    strategy: "Regular Backups",
    level: 1,
    text: "Backups of data, applications and settings are synchronised to enable restoration to a common point in time.",
    info: "Configure backup systems to create consistent recovery points across all systems, databases, and applications so they can be restored to the same point in time following an incident."
  },
  {
    id: "rb_l1_q3",
    strategy: "Regular Backups",
    level: 1,
    text: "Backups of data, applications and settings are retained in a secure and resilient manner.",
    info: "Store backups in a secure environment with encryption, access controls, and physical security measures, and ensure resilience through geographic separation or offline copies."
  },
  {
    id: "rb_l1_q4",
    strategy: "Regular Backups",
    level: 1,
    text: "Restoration of data, applications and settings from backups to a common point in time is tested as part of disaster recovery exercises.",
    info: "Conduct regular (at least quarterly) restoration testing to verify backup integrity and recovery procedures, validating that applications and data can be fully recovered in required timeframes."
  },
  {
    id: "rb_l1_q5",
    strategy: "Regular Backups",
    level: 1,
    text: "Unprivileged user accounts cannot access backups belonging to other user accounts.",
    info: "Configure backup systems with strict access controls ensuring users can only access their own backups, preventing data leakage or unauthorized access to sensitive information."
  },
  {
    id: "rb_l1_q6",
    strategy: "Regular Backups",
    level: 1,
    text: "Unprivileged user accounts are prevented from modifying and deleting backups.",
    info: "Implement technical controls to make backups immutable to regular users, preventing them from deleting or modifying backups which could facilitate ransomware attacks or data destruction."
  },
  {
    id: "rb_l2_q1",
    strategy: "Regular Backups",
    level: 2,
    text: "Privileged user accounts (excluding backup administrator accounts) cannot access backups belonging to other user accounts.",
    info: "Restrict access to individual user backups for IT administrators and other privileged accounts that don't specifically manage backups, limiting the blast radius if an admin account is compromised."
  },
  {
    id: "rb_l2_q2",
    strategy: "Regular Backups",
    level: 2,
    text: "Privileged user accounts (excluding backup administrator accounts) are prevented from modifying and deleting backups.",
    info: "Configure backup systems so even domain administrators and other privileged accounts cannot modify or delete backups, protecting against insider threats or compromised admin credentials."
  },
  {
    id: "rb_l3_q1",
    strategy: "Regular Backups",
    level: 3,
    text: "Unprivileged user accounts cannot access their own backups.",
    info: "Remove direct end-user access to backup systems entirely, requiring users to submit restoration requests through IT support to ensure proper verification and to prevent malware from accessing backups."
  },
  {
    id: "rb_l3_q2",
    strategy: "Regular Backups",
    level: 3,
    text: "Privileged user accounts (excluding backup administrator accounts) cannot access their own backups.",
    info: "Implement separation of duties for backup access so even users with administrative privileges cannot directly access their own backups, requiring a second administrator for restoration."
  },
  {
    id: "rb_l3_q3",
    strategy: "Regular Backups",
    level: 3,
    text: "Backup administrator accounts are prevented from modifying and deleting backups during their retention period.",
    info: "Use technical controls like WORM (Write Once Read Many) storage, retention locks, or dual-control approval processes to prevent even backup administrators from modifying or deleting backups until their defined retention period expires."
  }
];

export default questionsData;