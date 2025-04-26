import React, { useState } from 'react';
import PropTypes from 'prop-types';

const Recommendations = ({ results = { strategies: {}, overallMaturityLevel: 0 } }) => {
  const [expandedRecs, setExpandedRecs] = useState({});
  const [expandedControls, setExpandedControls] = useState({});

  const toggleExpand = (index) => {
    setExpandedRecs(prev => ({
      ...prev,
      [index]: !prev[index]
    }));
  };

  const toggleControlExpand = (recIndex, controlIndex) => {
    const key = `${recIndex}-${controlIndex}`;
    setExpandedControls(prev => ({
      ...prev,
      [key]: !prev[key]
    }));
  };

  const getControlSolution = (strategy, requirement) => {
    const solutions = {
      'Application Control': {
        'workstations': 'Deploy AppLocker or WDAC across all workstations. Only allow digitally signed or approved executables.',
        'user profiles': 'Harden user areas like temp folders, email download paths, and browser caches using GPO and allowlists.',
        'executables': 'Maintain a centrally managed application allowlist. Deny unsigned apps by default.',
        'default': 'Apply application allowlisting using enterprise tools to control script, installer and binary execution.'
      },
      'Patch Applications': {
        'asset discovery': 'Block domain admin accounts from logging in to user workstations. Enforce separation using logon restrictions and RDP filtering policies.',
        'up-to-date vulnerability database': 'Use jump servers for administrative access. These should be hardened, isolated, and monitored as high-value assets.',
        'daily to identify missing patches or updates for vulnerabilities in online services': 'Use password managers or vaults to store long, unique break glass and service account credentials. Enforce rotation and monitor changes.',
        'weekly to identify missing patches or updates for vulnerabilities in office productivity suites': 'Enable logging of privileged access events using Windows Event Forwarding or a SIEM. Track role changes and sensitive command usage.',
        'fortnightly to identify missing patches or updates for vulnerabilities in applications other than': 'Log all group membership and privileged account changes. Ensure logs are shipped to a secure location and reviewed periodically.',
        'applied within 48 hours of release when vulnerabilities are assessed as critical': 'Set logs as read-only or write-once using filesystem permissions or WORM storage. Monitor tampering attempts via audit logs.',
        'applied within two weeks of release when vulnerabilities are assessed as non-critical': 'Enable and collect logs from all internet-facing systems. Correlate with authentication logs to detect brute force and anomaly patterns.',
        'applied within two weeks of release': 'Correlate alerts and logs using SIEM rules. Use built-in correlation packs or custom rules based on attacker TTPs (MITRE ATT&CK).',
        'applied within one month of release': 'Create incident notification protocols and escalation workflows. Log incident response activities and responsible parties.',
        'no longer supported by vendors are removed': 'Follow mandatory reporting obligations to ASD for major cybersecurity incidents. Use the official reporting form and notify early.',
        'adobe flash player, and security products that are no longer supported': 'Maintain and rehearse a full incident response plan. Simulate real scenarios at least annually and document outcomes and lessons learned.',
        'default': 'Run regular asset scans, use a modern patch management tool, and remediate vulnerabilities on all software within vendor-recommended timeframes.'
      },
      'Patch Operating Systems': {
        'asset discovery': 'Ensure all privileged access is validated before provisioning. This includes manual approvals, ticketing system checks, or automated role validation.',
        'up-to-date vulnerability database': 'Disable privileged access if it hasn’t been revalidated within 12 months. Use automation or scheduled audits to flag accounts approaching expiry.',
        'daily to identify missing patches or updates for vulnerabilities in operating systems of internet-facing': 'Set up automatic deactivation of privileged access after 45 days of inactivity using scripts, AD policies, or identity governance tools.',
        'fortnightly to identify missing patches or updates for vulnerabilities in operating systems of workstations': 'Create separate privileged accounts (e.g., admin.jane) for tasks like system configuration and patching. Avoid daily-use for privileged sessions.',
        'applied within 48 hours of release when vulnerabilities are assessed as critical': 'Define precise scopes for system, app, and database access. Use RBAC models and avoid assigning blanket administrator privileges.',
        'applied within two weeks of release when vulnerabilities are assessed as non-critical': 'Apply web filtering or firewall rules that block privileged accounts from using browsers and email clients. Enforce GPO or Conditional Access.',
        'applied within one month of release': 'Configure firewall, proxy, or conditional access rules that only allow minimum online access for authorised privileged users or services.',
        'no longer supported by vendors are replaced': 'Install Secure Admin Workstations (SAWs) with hardened configurations, no internet access, and full monitoring. Use them only for admin tasks.',
        'default': 'Apply OS patches using WSUS, Endpoint Manager, or Red Hat Satellite. Ensure critical vulnerabilities are patched within 48 hours and others within 2 weeks or 1 month as per maturity level.'
      },
      'Configure Microsoft Office Macros': {
        'disabled for users that do not have a demonstrated business requirement': 'Block users from modifying browser security settings using Group Policy or Intune. Enforce hardened configurations at the policy level.',
        'files originating from the internet are blocked': 'Use Attack Surface Reduction (ASR) rules to block Office from launching child processes (e.g., cmd.exe, powershell.exe).',
        'macro antivirus scanning is enabled': 'Prevent Office apps from creating executable content (e.g., EXE, DLL). Block using ASR rules or endpoint policies.',
        'macros are blocked from making win32 api calls': 'Block Office applications from injecting code into other processes. This mitigates many macro-based attack chains.',
        'macro security settings cannot be changed by users': 'Disable Object Linking and Embedding (OLE) in Office. Prevent users from embedding malicious scripts in documents.',
        'default': 'Configure macro settings via Group Policy to block internet-originated files, enforce antivirus scanning, and disable Win32 API usage in Office macros.'
      },
      'User Application Hardening': {
        'internet explorer 11 is disabled or removed': 'Apply vendor and ASD Office hardening guidelines. Disable macros, restrict ActiveX, and enforce strict document origins.',
        'java from the internet': 'Restrict users from altering Office security settings. Lock down via Group Policy or Intune configuration profiles.',
        'web advertisements from the internet': 'Use ASR to prevent PDF readers from launching child processes like PowerShell or cmd.exe. Target Adobe Reader and other major apps.',
        'web browsers are hardened using asd and vendor hardening guidance': 'Apply Adobe’s and ASD’s hardening guidance to your PDF software. Remove JavaScript, limit embedded content, and enforce trust controls.',
        'web browser security settings cannot be changed by users': 'Lock PDF security settings with policies. Prevent user override by applying registry policies or managed configuration profiles.',
        'microsoft office is blocked from creating child processes': 'Uninstall or disable .NET Framework 3.5 (which includes 2.0 and 3.0) unless legacy apps require it. Use Windows Features or PowerShell.',
        'microsoft office is blocked from creating executable content': 'Remove PowerShell 2.0, which lacks modern security. Use DISM or Intune to remove the Windows feature.',
        'microsoft office is blocked from injecting code into other processes': 'Configure PowerShell to use Constrained Language Mode for untrusted processes and standard users. Prevents script abuse.',
        'prevent activation of object linking and embedding packages': 'Log all PowerShell module loads, script block content, and transcription events. Helps in detecting malicious use of PowerShell.',
        'office productivity suites are hardened using asd and vendor hardening guidance': 'Log all command-line process executions. Helps detect malware launched via cmd.exe or powershell.exe with suspicious parameters.',
        'office productivity suite security settings cannot be changed by users': 'Protect logs using WORM storage or strict ACLs. Prevent unauthorized users from modifying or deleting log entries.',
        'pdf software is blocked from creating child processes': 'Send logs from perimeter servers to a SIEM for real-time threat detection and correlation (VPN, web, email gateways).',
        'pdf software is hardened using asd and vendor hardening guidance': 'Aggregate logs from internal servers and check for unauthorized access, configuration changes, and failed logon attempts.',
        'pdf software security settings cannot be changed by users': 'Forward workstation logs to a central SIEM. Look for script-based attacks, new user creation, and privilege escalations.',
        'powershell module logging': 'Correlate events across servers, endpoints, and cloud apps to identify cybersecurity incidents. Use MITRE ATT&CK-aligned analytics.',
        'command line process creation events': 'Ensure critical incidents are reported to your CISO or designated delegate as soon as possible. Automate notifications from your SIEM or ticketing system.',
        'event logs are protected from unauthorised modification': 'Serious incidents involving data breaches, malware, or critical infrastructure should be reported to ASD through their official portal.',
        'event logs from internet-facing servers are analysed': 'Initiate your incident response plan (IRP) as soon as an incident is identified. Ensure all stakeholders know their roles and responsibilities.',
        'cybersecurity events are analysed in a timely manner': 'Use AppLocker, WDAC, or third-party tools to apply application control on workstations. Start in audit mode before full enforcement.',
        'incidents are reported to the chief information security officer': 'Deploy application control on internet-facing servers. Limit execution to a trusted set of applications signed by vendors or your org.',
        'incidents are reported to asd': 'Extend application control to internal/non-internet-facing servers. Prevent malware from spreading via lateral movement or file shares.',
        'incident response plan is enacted': 'Block execution in user profile folders and browser download directories. These are common malware entry points.',
        'default': 'Apply vendor security baselines and restrict risky features across Office, PDF software, browsers, and email clients using GPO, Intune, or CIS Benchmarks.'
      },
      'Restrict Admin Privileges': {
        'validated when first requested': 'Use inactivity-based deactivation policies for privileged accounts. Trigger account disablement after 45 days of non-use unless exempt.',
        'revalidated after 12 months': 'Provision dedicated admin accounts (e.g., admin.john) that are isolated from day-to-day email or web use. Monitor their login activity.',
        'disabled after 45 days of inactivity': 'Restrict access to systems and apps strictly to the permissions necessary. Remove inherited admin rights and use least privilege by default.',
        'dedicated privileged user account': 'Apply network and application policies that block privileged users from accessing external content. Enforce separation of duties for security.',
        'prevented from accessing the internet, email and web services': 'Only allow authorised privileged users online access. Restrict browser/email access using firewall rules, web proxy, or Conditional Access.',
        'strictly limited to only what is required': 'Use hardened Secure Admin Workstations (SAWs) for admin tasks. Block internet, email, USB, and restrict software installation.',
        'use separate privileged and unprivileged operating environments': 'Admins must use separate operating systems for privileged vs. unprivileged use. Prevent crossover by blocking logons and session hijack risks.',
        'not virtualised within unprivileged operating environments': 'Disallow hosting of privileged VMs inside unprivileged environments. Block hypervisor access or use endpoint control tools to monitor VM sprawl.',
        'unprivileged user accounts cannot logon to privileged operating environments': 'Enforce group policy or logon rights to block standard accounts from accessing domain controllers or admin workstations.',
        'privileged user accounts cannot logon to unprivileged operating environments': 'Block admin accounts from logging into user workstations using logon restrictions, firewall rules, and privileged access baselines.',
        'conducted through jump servers': 'Admin tasks must only be performed from jump servers with logging enabled. Block all admin access from unmanaged devices or BYOD endpoints.',
        'credentials for break glass accounts, local administrator accounts and service accounts': 'Use a password manager or secrets vault to create long, complex, unique credentials for break glass, local admin, and service accounts. Rotate periodically.',
        'privileged access events are centrally logged': 'Forward logs of successful/failed privilege access attempts to a central SIEM or log platform. Enable alerting for suspicious activity patterns.',
        'privileged user account and security group management events': 'Audit and forward all changes to privileged accounts or security groups to a SIEM. Trigger alerts on unauthorized group membership changes.',
        'event logs are protected from unauthorised modification': 'Set logs to write-once or protect with file integrity monitoring. Use tamper-evident storage or cloud-native retention policies.',
        'event logs from internet-facing servers are analysed': 'Analyze logs from perimeter-facing servers like web gateways and VPNs using a SIEM or XDR. Detect signs of scanning or brute force attacks.',
        'cybersecurity events are analysed in a timely manner': 'Configure internal server logs to capture authentication attempts, service startups, lateral movement attempts, and remote command execution.',
        'incidents are reported to the chief information security officer': 'Forward and analyze logs from all user workstations. Look for malware behavior, PowerShell abuse, and execution of suspicious binaries.',
        'incidents are reported to asd': 'Set SIEM rules to detect correlated events across users, hosts, and files. Use MITRE ATT&CK-based detection logic for better fidelity.',
        'incident response plan is enacted': 'Create internal SOPs for CISO notification upon incident discovery. Use automation via SIEM or ITSM where possible.',
        'default': 'Implement least privilege, enforce privileged separation with SAWs, and monitor all admin activity with centralised logging and alerting.'
      },
      'Multi-factor Authentication': {
        'their organisation’s online services that process, store or communicate their organisation’s sensitive data': 'Prevent the use of virtual machines to emulate admin environments from unprivileged workstations. Block virtualization features via GPO.',
        'third-party online services that process, store or communicate their organisation’s sensitive data': 'Restrict access to privileged environments by unprivileged users via login restrictions, firewall rules, and group membership enforcement.',
        'third-party online services that process, store or communicate their organisation’s non-sensitive data': 'Configure domain policies to deny privileged accounts logon access to unprivileged systems. Monitor violations using log analytics or SIEM.',
        'their organisation’s online customer services': 'Enable just-in-time (JIT) administration using tools like Azure PIM. Approvals should be required for time-bound elevated access.',
        'third-party online customer services': 'Route all administrative activities through hardened jump servers. Enforce access via RDP or bastion hosts with logging enabled.',
        'customers to online customer services that process, store or communicate sensitive customer data': 'Store service, local admin, and emergency credentials in a password vault. Enforce long, random values and periodic rotation.',
        'used to authenticate privileged users of systems': 'Enable event logging specifically for privilege elevation attempts, sudo commands, group membership changes, and access grants.',
        'used to authenticate unprivileged users of systems': 'Monitor group changes, user promotions, or admin role assignments using directory audit logs and alerting rules in your SIEM.',
        'uses either: something users have and something users know': 'Protect logs by configuring WORM (write once, read many) or hardened log stores with access control. Alert on tampering attempts.',
        'is phishing-resistant': 'Aggregate and review logs from external-facing systems like VPNs and mail servers. Focus on access attempts and failed logins.',
        'provides a phishing-resistant option': 'Review logs from non-internet-facing servers regularly. Focus on signs of lateral movement, brute force attempts, and service anomalies.',
        'used for authenticating users of systems is phishing-resistant': 'Workstation logs should be collected centrally. Focus on PowerShell usage, failed logins, suspicious file modifications.',
        'successful and unsuccessful multi-factor authentication events are centrally logged': 'Correlate workstation logs with threat intel feeds. Set alerts for script-based attacks, tool execution (e.g., mimikatz), and privilege escalation.',
        'event logs are protected from unauthorised modification and deletion': 'Set up automated alerts and dashboards to correlate and prioritize cybersecurity events across endpoints, users, and servers.',
        'event logs from internet-facing servers are analysed': 'Create internal procedures that mandate reporting all major incidents to the CISO or their delegate. Automate email/ticketing triggers if possible.',
        'cybersecurity events are analysed in a timely manner': 'Notify ASD of serious breaches or threats using their official online form. Include details on attack vector, affected systems, and data loss.',
        'incidents are reported to the chief information security officer': 'Document and rehearse a plan for immediate activation following an incident. Roles, contacts, and escalation paths must be pre-defined.',
        'incidents are reported to asd': 'Verify privileged access with tickets, identity governance rules, or manual validation before assigning any elevated permissions.',
        'incident response plan is enacted': 'Schedule periodic reviews to ensure privileged access is still needed. Deactivate dormant or unjustified accounts after 12 months max.',
        'default': 'Enforce MFA across all internal and external services using phishing-resistant methods. Audit and alert on all MFA-related activities.'
      },
      'Regular Backups': {
        'performed and retained in accordance with business criticality and business continuity requirements': 'Apply control to non-user folders, including mapped drives and custom paths. Use allowlists and cryptographic signatures.',
        'synchronised to enable restoration to a common point in time': 'Allow only digitally signed executables, scripts, and drivers from trusted publishers. Reduce risk from unsigned or altered code.',
        'retained in a secure and resilient manner': 'Use Microsoft’s recommended blocklist to prevent execution of known malicious or vulnerable software components.',
        'restoration of data, applications and settings from backups to a common point in time is tested': 'Review and validate application control rule sets annually or more frequently. Adjust rules based on new software, vulnerabilities, or business needs.',
        'unprivileged user accounts cannot access backups belonging to other user accounts': 'Log all allowed and blocked application control events. Forward logs to a SIEM for visibility into execution patterns and bypass attempts.',
        'default': 'Ensure backups are secure, regularly tested, and inaccessible to unprivileged users. Apply business-critical retention and protection policies.'
      }
    };

    const strategySolutions = solutions[strategy] || {};
    
    // Try matching a specific keyword
    const match = Object.entries(strategySolutions).find(([key]) =>
      key !== 'default' && requirement.toLowerCase().includes(key.toLowerCase())
    );

    // Fallback to default per strategy if no match
    return match ? match[1] : strategySolutions['default'] || 'Refer to ACSC Essential Eight guidance for implementation.';
  };

  const getControlTooling = (strategy) => {
    const tooling = {
      'Application Control': 'Microsoft AppLocker, Windows Defender Application Control (WDAC), Ivanti, Carbon Black',
      'Patch Applications': 'Microsoft SCCM, PDQ Deploy, Automox, Intune, WSUS, Tenable Nessus, Rapid7 InsightVM',
      'Patch Operating Systems': 'Microsoft Endpoint Manager, Intune, WSUS, Red Hat Satellite, Landscape (Ubuntu), Automox',
      'Configure Microsoft Office Macros': 'Group Policy Editor, Microsoft 365 Security Center, Intune Configuration Profiles',
      'User Application Hardening': 'Microsoft Security Baselines, CIS-CAT Pro, Chrome Enterprise Policies, Group Policy',
      'Restrict Admin Privileges': 'Microsoft LAPS, Azure AD PIM, BeyondTrust, CyberArk, Admin By Request',
      'Multi-factor Authentication': 'Microsoft Entra ID (Azure AD), Duo Security, YubiKey, Google Authenticator, Auth0 MFA',
      'Regular Backups': 'Veeam, Acronis, Microsoft Azure Backup, Commvault, Backblaze B2, AWS Backup'
    };
    return tooling[strategy] || 'Industry-standard enterprise security tools';
  };

  const getControlReferences = (strategy, requirement) => {
    const baseReferences = {
      'Patch Applications': [
        {
          title: 'ACSC Patch Management Guidance',
          url: 'https://www.cyber.gov.au/acsc/view-all-content/publications/assessing-security-vulnerabilities-and-patches'
        }
      ],
      'Patch Operating Systems': [
        {
          title: 'ACSC Patch Operating Systems Strategy',
          url: 'https://www.cyber.gov.au/acsc/view-all-content/publications/essential-eight-maturity-model'
        }
      ],
      'Multi-factor Authentication': [
        {
          title: 'ACSC MFA Guidance',
          url: 'https://www.cyber.gov.au/acsc/view-all-content/publications/multi-factor-authentication'
        }
      ],
      'Application Control': [
        {
          title: 'ACSC Application Control Guidelines',
          url: 'https://www.cyber.gov.au/acsc/view-all-content/publications/implementing-application-control'
        }
      ],
      'Configure Microsoft Office Macros': [
        {
          title: 'Microsoft Office Macro Blocking',
          url: 'https://www.cyber.gov.au/acsc/view-all-content/publications/implementing-microsoft-office-macro-security-controls'
        }
      ],
      'User Application Hardening': [
        {
          title: 'ACSC Hardening User Applications',
          url: 'https://www.cyber.gov.au/acsc/view-all-content/publications/hardening-user-applications'
        }
      ],
      'Restrict Admin Privileges': [
        {
          title: 'ACSC Admin Privilege Guidelines',
          url: 'https://www.cyber.gov.au/acsc/view-all-content/publications/restricting-administrative-privileges'
        }
      ],
      'Regular Backups': [
        {
          title: 'ACSC Regular Backups Guidelines',
          url: 'https://www.cyber.gov.au/acsc/view-all-content/publications/regular-backups'
        }
      ]
    };

    const specificReferences = {
      'Patch Applications': {
        'An automated method of asset discovery is used at least fortnightly': 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/device-discovery',
        'A vulnerability scanner with an up-to-date vulnerability database': 'https://docs.tenable.com/nessus/Content/AboutPlugins.htm',
        'A vulnerability scanner is used at least daily': 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-vuln-management/',
        'A vulnerability scanner is used at least weekly': 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-vuln-management/',
        'Patches, updates or other vendor mitigations for vulnerabilities in online services are applied within 48 hours': 'https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-for-business-configure',
        'Patches, updates or other vendor mitigations for vulnerabilities in online services are applied within two weeks': 'https://learn.microsoft.com/en-us/mem/intune/protect/windows-10-update-rings-configure',
        'Patches, updates or other vendor mitigations for vulnerabilities in office productivity suites': 'https://learn.microsoft.com/en-us/deployoffice/updates/overview-office-updates',
        'Online services that are no longer supported by vendors are removed': 'https://www.cyber.gov.au/acsc/view-all-content/advisories/assessing-legacy-services',
        'Office productivity suites, web browsers and their extensions, email clients, PDF software, Adobe Flash Player, and security products that are no longer supported by vendors are removed': 'https://learn.microsoft.com/en-us/mem/intune/apps/apps-deploy',
        'A vulnerability scanner is used at least weekly to identify missing patches or updates for vulnerabilities in office productivity suites, web browsers and their extensions, email clients, PDF software, and security products.': 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-vuln-management/',
        'Patches, updates or other vendor mitigations for vulnerabilities in online services are applied within 48 hours of release when vulnerabilities are assessed as critical by vendors or when working exploits exist.': 'https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-for-business-configure',
        'Patches, updates or other vendor mitigations for vulnerabilities in online services are applied within two weeks of release when vulnerabilities are assessed as non-critical by vendors and no working exploits exist.': 'https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-for-business-configure',
        'Patches, updates or other vendor mitigations for vulnerabilities in office productivity suites, web browsers and their extensions, email clients, PDF software, and security products are applied within two weeks of release.': 'https://learn.microsoft.com/en-us/deployoffice/updates/overview-office-updates',
        'Online services that are no longer supported by vendors are removed.': 'https://www.cyber.gov.au/acsc/view-all-content/advisories/assessing-legacy-services',
        'Office productivity suites, web browsers and their extensions, email clients, PDF software, Adobe Flash Player, and security products that are no longer supported by vendors are removed.': 'https://learn.microsoft.com/en-us/windows/deployment/planning/windows-11-deprecation-removal',
        'A vulnerability scanner is used at least fortnightly to identify missing patches or updates for vulnerabilities in applications other than office productivity suites, web browsers and their extensions, email clients, PDF software, and security products.': 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-vuln-management/vulnerability-assessment-overview',
        'Patches, updates or other vendor mitigations for vulnerabilities in applications other than office productivity suites, web browsers and their extensions, email clients, PDF software, and security products are applied within one month of release.': 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-vuln-management/vulnerability-assessment-overview',
        'Patches, updates or other vendor mitigations for vulnerabilities in office productivity suites, web browsers and their extensions, email clients, PDF software, and security products are applied within 48 hours of release when vulnerabilities are assessed as critical by vendors or when working exploits exist.': 'https://learn.microsoft.com/en-us/deployoffice/updates/overview-office-updates',
        'Patches, updates or other vendor mitigations for vulnerabilities in office productivity suites, web browsers and their extensions, email clients, PDF software, and security products are applied within two weeks of release when vulnerabilities are assessed as non-critical by vendors and no working exploits exist.': 'https://learn.microsoft.com/en-us/deployoffice/updates/overview-office-updates',
        'Applications other than office productivity suites, web browsers and their extensions, email clients, PDF software, Adobe Flash Player, and security products that are no longer supported by vendors are removed.': 'https://learn.microsoft.com/en-us/windows/deployment/planning/windows-11-deprecation-removal',
      },
      'Patch Operating Systems': {
        'An automated method of asset discovery is used at least fortnightly': 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/device-discovery',
        'A vulnerability scanner with an up-to-date vulnerability database': 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-vuln-management/',
        'A vulnerability scanner is used at least daily to identify missing patches or updates for vulnerabilities in operating systems of internet-facing': 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-vuln-management/',
        'A vulnerability scanner is used at least fortnightly to identify missing patches or updates for vulnerabilities in operating systems of workstations': 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-vuln-management/',
        'Patches, updates or other vendor mitigations for vulnerabilities in operating systems of internet-facing servers and internet-facing network devices are applied within 48 hours': 'https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-for-business-configure',
        'Patches, updates or other vendor mitigations for vulnerabilities in operating systems of internet-facing servers and internet-facing network devices are applied within two weeks': 'https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-for-business-configure',
        'Patches, updates or other vendor mitigations for vulnerabilities in operating systems of workstations, non-internet-facing servers and non-internet-facing network devices are applied within one month': 'https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-for-business-configure',
        'Operating systems that are no longer supported by vendors are replaced': 'https://learn.microsoft.com/en-us/windows/whats-new/whats-new-windows-11',
        'Event logs are protected from unauthorised modification and deletion.': 'https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-data-security',
        'Event logs from internet-facing servers are analysed in a timely manner to detect cyber security events.': 'https://learn.microsoft.com/en-us/azure/sentinel/connect-windows-security-events',
        'A vulnerability scanner is used at least fortnightly to identify missing patches or updates for vulnerabilities in drivers.': 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-vuln-management/vulnerability-assessment-overview',
        'A vulnerability scanner is used at least fortnightly to identify missing patches or updates for vulnerabilities in firmware.': 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-vuln-management/vulnerability-assessment-overview',
        'Patches, updates or other vendor mitigations for vulnerabilities in operating systems of workstations, non-internet-facing servers and non-internet-facing network devices are applied within 48 hours of release when vulnerabilities are assessed as critical by vendors or when working exploits exist.': 'https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-for-business-configure',
        'Patches, updates or other vendor mitigations for vulnerabilities in operating systems of workstations, non-internet-facing servers and non-internet-facing network devices are applied within one month of release when vulnerabilities are assessed as non-critical by vendors and no working exploits exist.': 'https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-for-business-configure',
        'Patches, updates or other vendor mitigations for vulnerabilities in drivers are applied within 48 hours of release when vulnerabilities are assessed as critical by vendors or when working exploits exist.': 'https://learn.microsoft.com/en-us/windows-hardware/drivers/install/using-windows-update-to-distribute-drivers',
        'Patches, updates or other vendor mitigations for vulnerabilities in drivers are applied within one month of release when vulnerabilities are assessed as non-critical by vendors and no working exploits exist.': 'https://learn.microsoft.com/en-us/windows-hardware/drivers/install/using-windows-update-to-distribute-drivers',
        'Patches, updates or other vendor mitigations for vulnerabilities in firmware are applied within 48 hours of release when vulnerabilities are assessed as critical by vendors or when working exploits exist.': 'https://learn.microsoft.com/en-us/mem/intune/protect/windows-update-for-business-configure',
        'Patches, updates or other vendor mitigations for vulnerabilities in firmware are applied within one month of release when vulnerabilities are assessed as non-critical by vendors and no working exploits exist.': 'https://learn.microsoft.com/en-us/mem/intune/protect/windows-update-for-business-configure',
        'The latest release, or the previous release, of operating systems are used.': 'https://learn.microsoft.com/en-us/windows/whats-new/whats-new-windows-11',
        'Event logs from non-internet-facing servers are analysed in a timely manner to detect cyber security events.': 'https://learn.microsoft.com/en-us/azure/sentinel/connect-windows-security-events',
        'Event logs from workstations are analysed in a timely manner to detect cyber security events.': 'https://learn.microsoft.com/en-us/azure/sentinel/connect-windows-security-events',
      },
      'Multi-factor Authentication': {
        'Multi-factor authentication is used to authenticate users to their organisation’s online services': 'https://learn.microsoft.com/en-us/microsoft-365/admin/security-and-compliance/set-up-multi-factor-authentication',
        'Multi-factor authentication is used to authenticate users to third-party online services': 'https://learn.microsoft.com/en-us/azure/active-directory/authentication/tutorial-enable-azure-mfa',
        'Multi-factor authentication (where available) is used to authenticate users to third-party online services': 'https://learn.microsoft.com/en-us/azure/active-directory/authentication/tutorial-enable-azure-mfa',
        'Multi-factor authentication is used to authenticate users to their organisation’s online customer services': 'https://learn.microsoft.com/en-us/azure/active-directory-b2c/custom-policy-overview',
        'Multi-factor authentication is used to authenticate users to third-party online customer services': 'https://learn.microsoft.com/en-us/azure/active-directory/external-identities/secure-external-sharing',
        'Multi-factor authentication is used to authenticate customers to online customer services': 'https://learn.microsoft.com/en-us/azure/active-directory-b2c/multi-factor-authentication',
        'Multi-factor authentication uses either: something users have and something users know': 'https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks',
        'Multi-factor authentication is used to authenticate users to their organisation’s online services that process, store or communicate their organisation’s sensitive data.': 'https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks',
        'Multi-factor authentication is used to authenticate users to their organisation’s online customer services that process, store or communicate their organisation’s sensitive customer data.': 'https://learn.microsoft.com/en-us/azure/active-directory/b2c/custom-policy-overview',
        'Multi-factor authentication is used to authenticate privileged users of systems.': 'https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-policy-mfa',
        'Multi-factor authentication is used to authenticate unprivileged users of systems.': 'https://learn.microsoft.com/en-us/azure/active-directory/authentication/tutorial-enable-azure-mfa',
        'Multi-factor authentication used for authenticating users of online services is phishing-resistant.': 'https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-phishing-resistant-authentication',
        'Multi-factor authentication used for authenticating customers of online customer services provides a phishing-resistant option.': 'https://learn.microsoft.com/en-us/azure/active-directory/b2c/multi-factor-authentication',
        'Multi-factor authentication used for authenticating users of systems is phishing-resistant.': 'https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-phishing-resistant-authentication',
        'Successful and unsuccessful multi-factor authentication events are centrally logged.': 'https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/concept-sign-ins',
        'Event logs are protected from unauthorised modification and deletion.': 'https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-data-security',
        'Event logs from internet-facing servers are analysed in a timely manner to detect cyber security events.': 'https://learn.microsoft.com/en-us/azure/sentinel/connect-windows-security-events',
        'Multi-factor authentication is used to authenticate users of data repositories.': 'https://learn.microsoft.com/en-us/azure/active-directory/authentication/tutorial-enable-azure-mfa',
        'Multi-factor authentication used for authenticating customers of online customer services is phishing-resistant.': 'https://learn.microsoft.com/en-us/azure/active-directory/b2c/multi-factor-authentication',
        'Multi-factor authentication used for authenticating users of data repositories is phishing-resistant.': 'https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-phishing-resistant-authentication',
        'Event logs from non-internet-facing servers are analysed in a timely manner to detect cyber security events.': 'https://learn.microsoft.com/en-us/azure/sentinel/connect-windows-security-events',
        'Event logs from workstations are analysed in a timely manner to detect cyber security events.': 'https://learn.microsoft.com/en-us/azure/sentinel/connect-windows-security-events',
      },
      'Restrict Admin Privileges': {
        'Requests for privileged access to systems, applications and data repositories are validated when first requested.': 'https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-how-to-activate-role',
        'Privileged users are assigned a dedicated privileged user account to be used solely for duties requiring privileged access.': 'https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-best-practices#use-separate-accounts-for-administrative-tasks',
        'Privileged user accounts (excluding those explicitly authorised to access online services) are prevented from accessing the internet, email and web services.': 'https://learn.microsoft.com/en-us/windows-server/administration/server-core/server-core-security',
        'Privileged user accounts explicitly authorised to access online services are strictly limited to only what is required for users and services to undertake their duties.': 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-privileged-access#use-least-privilege-principle',
        'Privileged users use separate privileged and unprivileged operating environments.': 'https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material',
        'Unprivileged user accounts cannot logon to privileged operating environments.': 'https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material',
        'Privileged user accounts (excluding local administrator accounts) cannot logon to unprivileged operating environments.': 'https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-workstations',
        'Privileged access to systems, applications and data repositories is disabled after 12 months unless revalidated.': 'https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-how-to-start-security-review',
        'Privileged access to systems and applications is disabled after 45 days of inactivity.': 'https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-how-to-start-security-review',
        'Privileged operating environments are not virtualised within unprivileged operating environments.': 'https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material#tiered-administration-model',
        'Administrative activities are conducted through jump servers.': 'https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-jump-servers',
        'Credentials for break glass accounts, local administrator accounts and service accounts are long, unique, unpredictable and managed.': 'https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-best-practices#emergency-access-accounts-break-glass-accounts',
        'Privileged access events are centrally logged.': 'https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/concept-audit-logs',
        'Privileged user account and security group management events are centrally logged.': 'https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/concept-audit-logs',
        'Event logs are protected from unauthorised modification and deletion.': 'https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-data-security',
        'Event logs from internet-facing servers are analysed in a timely manner to detect cyber security events.': 'https://learn.microsoft.com/en-us/azure/sentinel/connect-windows-security-events',
        'Privileged access to systems, applications and data repositories is limited to only what is required for users and services to undertake their duties.': 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-privileged-access#use-least-privilege-principle',
        'Secure Admin Workstations are used in the performance of administrative activities.': 'https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-workstations',
        'Just-in-time administration is used for administering systems and applications.': 'https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-configure',
        'Memory integrity functionality is enabled.': 'https://learn.microsoft.com/en-us/windows/security/information-protection/device-guard/enable-virtualization-based-protection-of-code-integrity',
        'Local Security Authority protection functionality is enabled.': 'https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection',
        'Credential Guard functionality is enabled.': 'https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard',
        'Remote Credential Guard functionality is enabled.': 'https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard',
        'Event logs from non-internet-facing servers are analysed in a timely manner to detect cyber security events.': 'https://learn.microsoft.com/en-us/azure/sentinel/connect-windows-security-events',
        'Event logs from workstations are analysed in a timely manner to detect cyber security events.': 'https://learn.microsoft.com/en-us/azure/sentinel/connect-windows-security-events',
      },
      'Application Control': {
        'Application control is implemented on workstations.': 'https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview',
        'Application control is applied to user profiles and temporary folders used by operating systems, web browsers and email clients.': 'https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/create-wdac-policy-using-intune',
        'Application control restricts the execution of executables, software libraries, scripts, installers, compiled HTML, HTML applications and control panel applets to an organisation-approved set.': 'https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control',
        'Application control is implemented on internet-facing servers.': 'https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control',
        'Application control is applied to all locations other than user profiles and temporary folders used by operating systems, web browsers and email clients.': 'https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/deployment-guide',
        'Microsoft’s recommended application blocklist is implemented.': 'https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules',
        'Application control rulesets are validated on an annual or more frequent basis.': 'https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/design-application-control-policies',
        'Allowed and blocked application control events are centrally logged.': 'https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/event-management',
        'Event logs are protected from unauthorised modification and deletion.': 'https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-data-security',
        'Event logs from internet-facing servers are analysed in a timely manner to detect cyber security events.': 'https://learn.microsoft.com/en-us/azure/sentinel/connect-windows-security-events',
        'Application control is implemented on non-internet-facing servers.': 'https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control',
        'Application control restricts the execution of drivers to an organisation-approved set.': 'https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/deployment-guide#driver-enforcement',
        'Microsoft’s vulnerable driver blocklist is implemented.': 'https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules',
        'Event logs from non-internet-facing servers are analysed in a timely manner to detect cyber security events.': 'https://learn.microsoft.com/en-us/azure/sentinel/connect-windows-security-events',
        'Event logs from workstations are analysed in a timely manner to detect cyber security events.': 'https://learn.microsoft.com/en-us/azure/sentinel/connect-windows-security-events',

      },
      'Configure Microsoft Office Macros': {
        'Microsoft Office macros are disabled for users that do not have a demonstrated business requirement.': 'https://learn.microsoft.com/en-us/deployoffice/security/manage-macro-settings-in-office-documents',
        'Microsoft Office macros in files originating from the internet are blocked.': 'https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked',
        'Microsoft Office macro antivirus scanning is enabled.': 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/enable-macro-antivirus-scanning',
        'Microsoft Office macro security settings cannot be changed by users.': 'https://learn.microsoft.com/en-us/deployoffice/security/group-policy-settings-for-blocking-macros',
        'Microsoft Office macros are blocked from making Win32 API calls.': 'https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked#additional-security-settings-for-macros',
        'Only Microsoft Office macros running from within a sandboxed environment, a Trusted Location or that are digitally signed by a trusted publisher are allowed to execute.': 'https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked#safe-locations-and-trusted-publishers',
        'Microsoft Office macros are checked to ensure they are free of malicious code before being digitally signed or placed within Trusted Locations.': 'https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked#security-best-practices-for-macro-management',
        'Only privileged users responsible for checking that Microsoft Office macros are free of malicious code can write to and modify content within Trusted Locations.': 'https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked#safe-locations-and-trusted-publishers',
        'Microsoft Office macros digitally signed by an untrusted publisher cannot be enabled via the Message Bar or Backstage View.': 'https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked#security-best-practices-for-macro-management',
        'Microsoft Office macros digitally signed by signatures other than V3 signatures cannot be enabled via the Message Bar or Backstage View.': 'https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked#security-best-practices-for-macro-management',
        'Microsoft Office’s list of trusted publishers is validated on an annual or more frequent basis.': 'https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked#safe-locations-and-trusted-publishers',
      },
      'User Application Hardening': {
        'Internet Explorer 11 is disabled or removed.': 'https://learn.microsoft.com/en-us/deployedge/microsoft-edge-ie-mode#disable-internet-explorer-11',
        'Web browsers do not process Java from the internet.': 'https://learn.microsoft.com/en-us/internet-explorer/ie11-deploy-guide/turn-off-java-in-internet-explorer',
        'Web browsers do not process web advertisements from the internet.': 'https://learn.microsoft.com/en-us/microsoft-edge/deploy/group-policies/tracking-prevention-group-policy',
        'Web browser security settings cannot be changed by users.': 'https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies',
        'Web browsers are hardened using ASD and vendor hardening guidance, with the most restrictive guidance taking precedence when conflicts occur.': 'https://learn.microsoft.com/en-us/deployedge/microsoft-edge-security-for-business',
        'Microsoft Office is blocked from creating child processes.': 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/attack-surface-reduction-rules?view=o365-worldwide#block-office-applications-from-creating-child-processes',
        'Microsoft Office is blocked from creating executable content.': 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/attack-surface-reduction-rules?view=o365-worldwide#block-office-applications-from-creating-executable-content',
        'Microsoft Office is blocked from injecting code into other processes.': 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/attack-surface-reduction-rules?view=o365-worldwide#block-office-applications-from-injecting-code-into-other-processes',
        'Microsoft Office is configured to prevent activation of Object Linking and Embedding packages.': 'https://learn.microsoft.com/en-us/deployoffice/security/office-internet-oembed-controls',
        'Office productivity suites are hardened using ASD and vendor hardening guidance, with the most restrictive guidance taking precedence when conflicts occur.': 'https://learn.microsoft.com/en-us/deployoffice/security/office-security-baselines',
        'Office productivity suite security settings cannot be changed by users.': 'https://learn.microsoft.com/en-us/deployoffice/security/group-policy-settings-for-office',
        'PDF software is blocked from creating child processes.': 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/attack-surface-reduction-rules?view=o365-worldwide#use-attack-surface-reduction-rules-to-control-pdf-reader-behavior',
        'PDF software is hardened using ASD and vendor hardening guidance, with the most restrictive guidance taking precedence when conflicts occur.': 'https://helpx.adobe.com/acrobat/using/protected-mode-windows.html',
        'PDF software security settings cannot be changed by users.': 'https://helpx.adobe.com/acrobat/using/protected-mode-windows.html',
        'PowerShell module logging, script block logging and transcription events are centrally logged.': 'https://learn.microsoft.com/en-us/powershell/scripting/windows-powershell/wmf/logging-improvements?view=powershell-7.2',
        'Command line process creation events are centrally logged.': 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor',
        'Event logs are protected from unauthorised modification and deletion.': 'https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-data-security',
        'Event logs from internet-facing servers are analysed in a timely manner to detect cyber security events.': 'https://learn.microsoft.com/en-us/azure/sentinel/connect-windows-security-events',
        '.NET Framework 3.5 (includes .NET 2.0 and 3.0) is disabled or removed.': 'https://learn.microsoft.com/en-us/windows/application-management/apps-in-windows-10#managing-optional-features',
        'Windows PowerShell 2.0 is disabled or removed.': 'https://learn.microsoft.com/en-us/powershell/scripting/windows-powershell/wmf/whats-new/whats-new-wmf5?view=powershell-7.2#powershell-20-deprecation',
        'PowerShell is configured to use Constrained Language Mode.': 'https://learn.microsoft.com/en-us/powershell/scripting/security/constrained-language-mode?view=powershell-7.2',
        'Event logs from non-internet-facing servers are analysed in a timely manner to detect cyber security events.': 'https://learn.microsoft.com/en-us/azure/sentinel/connect-windows-security-events',
        'Event logs from workstations are analysed in a timely manner to detect cyber security events.': 'https://learn.microsoft.com/en-us/azure/sentinel/connect-windows-security-events',

      },
      'Regular Backups': {
        'Backups of data, applications and settings are performed and retained in accordance with business criticality and business continuity requirements.': 'https://learn.microsoft.com/en-us/azure/backup/backup-overview',
        'Backups of data, applications and settings are synchronised to enable restoration to a common point in time.': 'https://learn.microsoft.com/en-us/azure/backup/backup-azure-arm-restore-vms#recovery-points',
        'Backups of data, applications and settings are retained in a secure and resilient manner.': 'https://learn.microsoft.com/en-us/azure/backup/backup-azure-rbac',
        'Restoration of data, applications and settings from backups to a common point in time is tested as part of disaster recovery exercises.': 'https://learn.microsoft.com/en-us/azure/site-recovery/azure-to-azure-test-failover',
        'Unprivileged user accounts cannot access backups belonging to other user accounts.': 'https://learn.microsoft.com/en-us/azure/backup/backup-azure-security-overview',
        'Unprivileged user accounts are prevented from modifying and deleting backups.': 'https://learn.microsoft.com/en-us/azure/backup/backup-azure-security-overview#prevent-deletion-of-recovery-services-vaults',
        'Privileged user accounts (excluding backup administrator accounts) cannot access backups belonging to other user accounts.': 'https://learn.microsoft.com/en-us/azure/backup/backup-azure-security-overview#access-control-and-data-protection',
        'Privileged user accounts (excluding backup administrator accounts) are prevented from modifying and deleting backups.': 'https://learn.microsoft.com/en-us/azure/backup/backup-azure-security-overview#soft-delete-and-protection-against-accidental-or-malicious-deletion',
        'Unprivileged user accounts cannot access their own backups.': 'https://learn.microsoft.com/en-us/azure/backup/backup-azure-security-overview#access-control-and-data-protection',
        'Privileged user accounts (excluding backup administrator accounts) cannot access their own backups.': 'https://learn.microsoft.com/en-us/azure/backup/backup-azure-security-overview#access-control-and-data-protection',
        'Backup administrator accounts are prevented from modifying and deleting backups during their retention period.': 'https://learn.microsoft.com/en-us/azure/backup/backup-azure-security-overview#soft-delete-and-protection-against-accidental-or-malicious-deletion'
      }
    };

    const baseRefs = baseReferences[strategy] || [];
    const matchedRefs = specificReferences[strategy];

    if (!matchedRefs || typeof requirement !== 'string') return baseRefs;

    const matchedEntry = Object.entries(matchedRefs).find(([key]) =>
      requirement.toLowerCase().includes(key.toLowerCase())
    );

    const getReadableTitleFromUrl = (url) => {
      try {
        const parsedUrl = new URL(url);
        const domain = parsedUrl.hostname;

        let vendor = 'Reference';
        if (domain.includes('microsoft.com')) vendor = 'Microsoft';
        else if (domain.includes('cyber.gov.au')) vendor = 'ACSC';
        else if (domain.includes('automox.com')) vendor = 'Automox';
        else if (domain.includes('qualys.com')) vendor = 'Qualys';
        else if (domain.includes('tenable.com')) vendor = 'Tenable';
        else if (domain.includes('manageengine.com')) vendor = 'ManageEngine';
        else if (domain.includes('auth0.com')) vendor = 'Auth0';
        else if (domain.includes('elastic.co')) vendor = 'Elastic';
        else if (domain.includes('duo.com')) vendor = 'Duo';
        else if (domain.includes('xero.com')) vendor = 'Xero';
        else if (domain.includes('cisa.gov')) vendor = 'CISA';
        else if (domain.includes('greenbone.net')) vendor = 'Greenbone';
        else if (domain.includes('heimdalsecurity.com')) vendor = 'Heimdal';
        else if (domain.includes('support')) vendor = 'Support';

        const segments = parsedUrl.pathname.split('/');
        const lastSegment = segments.pop() || segments.pop(); // handle trailing slash

        const cleanTitle = lastSegment
          .replace(/[-_]/g, ' ')
          .replace(/\..+$/, '') // strip file extensions
          .replace(/\b\w/g, c => c.toUpperCase());

        return `${vendor}: ${cleanTitle}`;
      } catch (err) {
        return 'Reference';
      }
    };

    const specificRef = matchedEntry
      ? [{ title: getReadableTitleFromUrl(matchedEntry[1]), url: matchedEntry[1] }]
      : [];

    return [...specificRef, ...baseRefs];
  };

  // Create recommendations based on assessment results
  const createRecommendations = () => {
    const recommendations = [];
    const strategies = Object.keys(results.strategies);
    
    // Add general recommendation based on overall maturity level
    switch (results.overallMaturityLevel) {
      case 0:
        recommendations.push({
          title: "Establish basic security foundations",
          description: "Your organization needs to establish foundational security controls. Focus on implementing Level 1 controls for all Essential Eight strategies, starting with the most critical gaps."
        });
        break;
      case 1:
        recommendations.push({
          title: "Progress to Level 2 maturity",
          description: "Build on your Level 1 foundations by addressing gaps in Level 2 requirements. Prioritize strategies with the lowest compliance scores."
        });
        break;
      case 2:
        recommendations.push({
          title: "Advance to Level 3 maturity",
          description: "Your organization has established good security practices. Focus now on advancing to Level 3 by implementing advanced controls, particularly for high-risk areas."
        });
        break;
      case 3:
        recommendations.push({
          title: "Maintain and enhance security posture",
          description: "Continue to maintain your strong security posture and consider enhancing beyond the Essential Eight framework with additional controls and security measures."
        });
        break;
      default:
        break;
    }
    
    // Add strategy-specific recommendations
    strategies.forEach(strategy => {
      const { maturityLevel, gaps } = results.strategies[strategy];
      const nextLevel = maturityLevel < 3 ? maturityLevel + 1 : null;
      
      if (nextLevel && gaps[nextLevel] && gaps[nextLevel].length > 0) {
        let priorityText = "";
        const compliancePercentage = results.strategies[strategy].compliance[nextLevel] || 0;
        
        if (compliancePercentage < 30) {
          priorityText = "High priority";
        } else if (compliancePercentage < 70) {
          priorityText = "Medium priority";
        } else {
          priorityText = "Low priority";
        }

        // Add detailed control information for each gap
        const controls = gaps[nextLevel].map(gap => ({
          name: strategy,
          requirement: gap,
          solution: getControlSolution(strategy, gap),
          tooling: getControlTooling(strategy),
          references: getControlReferences(strategy, gap)
        }));
        
        recommendations.push({
          title: `Improve ${strategy} (${priorityText})`,
          description: `Address ${gaps[nextLevel].length} gaps to achieve Level ${nextLevel} maturity.`,
          items: gaps[nextLevel],
          controls: controls,
          moreCount: gaps[nextLevel].length > 3 ? gaps[nextLevel].length - 3 : 0
        });
      }
    });
    
    return recommendations;
  };

  const recommendations = createRecommendations();

  return (
    <div className="space-y-4">
      {recommendations.map((rec, index) => (
        <div 
          key={index} 
          className="bg-gray-50 rounded-lg p-4"
          data-full-items={rec.items ? JSON.stringify(rec.items) : '[]'}
        >
          <h4 className="font-semibold text-primary mb-2">{rec.title}</h4>
          <p className="text-gray-700 mb-3">{rec.description}</p>
          
          {rec.controls && rec.controls.length > 0 && (
            <div className="ml-4">
              <div className="space-y-4">
                {(expandedRecs[index] ? rec.controls : rec.controls.slice(0, 3)).map((control, controlIndex) => (
                  <div key={controlIndex} className="border border-gray-200 rounded-lg p-4 bg-white">
                    <div className="flex justify-between items-start">
                      <div className="space-y-2 flex-1">
                        <h5 className="font-medium text-gray-900">{control.requirement}</h5>
                        <div className="text-sm text-gray-600">
                          <p className="font-medium mb-1">Proposed Solution:</p>
                          <p>{control.solution}</p>
                        </div>
                        {expandedControls[`${index}-${controlIndex}`] && (
                          <>
                            <div className="text-sm text-gray-600">
                              <p className="font-medium mb-1">Recommended Tools:</p>
                              <p>{control.tooling}</p>
                            </div>
                            <div className="text-sm text-gray-600">
                              <p className="font-medium mb-1">References:</p>
                              <ul className="list-none space-y-1">
                                {control.references.map((ref, refIndex) => (
                                  <li key={refIndex}>
                                    <a 
                                      href={ref.url}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="text-blue-600 hover:underline"
                                    >
                                      {ref.title}
                                    </a>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          </>
                        )}
                      </div>
                      <button
                        onClick={() => toggleControlExpand(index, controlIndex)}
                        className="ml-4 text-primary hover:text-primary-dark"
                      >
                        {expandedControls[`${index}-${controlIndex}`] ? 'Show less' : 'Show more'}
                      </button>
                    </div>
                  </div>
                ))}
                {!expandedRecs[index] && rec.moreCount > 0 && (
                  <button 
                    onClick={() => toggleExpand(index)}
                    className="text-primary hover:underline italic cursor-pointer block w-full text-center"
                  >
                    Show {rec.moreCount} more improvements...
                  </button>
                )}
                {expandedRecs[index] && rec.moreCount > 0 && (
                  <button 
                    onClick={() => toggleExpand(index)}
                    className="text-primary hover:underline italic cursor-pointer block w-full text-center"
                  >
                    Show less
                  </button>
                )}
              </div>
            </div>
          )}
          
          {(!rec.controls || rec.controls.length === 0) && (
            <div className="text-center italic text-gray-500">
              No specific recommendations available.
            </div>
          )}
        </div>
      ))}
    </div>
  );
};

Recommendations.propTypes = {
  results: PropTypes.shape({
    strategies: PropTypes.object.isRequired,
    overallMaturityLevel: PropTypes.number.isRequired
  }).isRequired
};

export default Recommendations;