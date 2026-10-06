-- ArcRadar DEMO seed data. LOCAL DEVELOPMENT ONLY.
--
-- * Runs automatically on `supabase db reset` (local stack). `supabase db push` never runs it.
-- * Creates four demo users with a publicly known password. Never run this against a
--   production database.
-- * Every row is marked origin = 'demo' and is fictional or documentation-range data:
--   IPs are RFC 5737 / RFC 3849 documentation addresses, domains use reserved TLDs
--   (.example, .test), hashes are digests of made-up strings. CVE entries are short
--   summaries of public vulnerabilities; verify details against NVD before relying on them.
--
-- Demo users (password for all: ArcRadar-Demo-1!):
--   admin@arcradar.test (Admin), analyst@arcradar.test (SOC L2), l1@arcradar.test (SOC L1),
--   viewer@arcradar.test (Viewer)

-- Lookup helpers, session-scoped (pg_temp) so nothing is left behind in the schema.
create function pg_temp.ind(v text) returns uuid language sql stable as
  $$ select id from public.indicators where value = v $$;
create function pg_temp.tag(n text) returns uuid language sql stable as
  $$ select id from public.tags where lower(name) = lower(n) $$;
create function pg_temp.inv(t text) returns uuid language sql stable as
  $$ select id from public.investigations where title = t $$;
create function pg_temp.alrt(t text) returns uuid language sql stable as
  $$ select id from public.alerts where title = t $$;
create function pg_temp.sha256_of(n int) returns text language sql immutable as
  $$ select encode(sha256(convert_to('arcradar-demo-sample-' || n, 'UTF8')), 'hex') $$;

-- ---------------------------------------------------------------------------
-- Demo users (profiles are created by the on_auth_user_created trigger)
-- ---------------------------------------------------------------------------
insert into auth.users (
  instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
  raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
  confirmation_token, recovery_token, email_change_token_new, email_change,
  email_change_token_current, phone_change, phone_change_token, reauthentication_token
)
select
  '00000000-0000-0000-0000-000000000000', u.id, 'authenticated', 'authenticated', u.email,
  extensions.crypt('ArcRadar-Demo-1!', extensions.gen_salt('bf')), now(),
  '{"provider":"email","providers":["email"]}'::jsonb,
  jsonb_build_object('display_name', u.display_name),
  now(), now(), '', '', '', '', '', '', '', ''
from (values
  ('aaaaaaaa-0000-4000-8000-000000000001'::uuid, 'admin@arcradar.test', 'Demo Admin'),
  ('aaaaaaaa-0000-4000-8000-000000000002'::uuid, 'analyst@arcradar.test', 'Demo Analyst'),
  ('aaaaaaaa-0000-4000-8000-000000000003'::uuid, 'viewer@arcradar.test', 'Demo Viewer'),
  ('aaaaaaaa-0000-4000-8000-000000000004'::uuid, 'l1@arcradar.test', 'Demo L1 Analyst')
) as u (id, email, display_name);

insert into auth.identities (provider_id, user_id, identity_data, provider, last_sign_in_at, created_at, updated_at)
select u.id::text, u.id,
  jsonb_build_object('sub', u.id::text, 'email', u.email, 'email_verified', true),
  'email', now(), now(), now()
from auth.users u
where u.email like '%@arcradar.test';

update public.profiles set role_name = 'admin' where id = 'aaaaaaaa-0000-4000-8000-000000000001';
update public.profiles set role_name = 'soc_l2' where id = 'aaaaaaaa-0000-4000-8000-000000000002';
update public.profiles set role_name = 'soc_l1' where id = 'aaaaaaaa-0000-4000-8000-000000000004';

-- ---------------------------------------------------------------------------
-- Tags
-- ---------------------------------------------------------------------------
insert into public.tags (name, color) values
  ('c2', '#ef4444'),
  ('phishing', '#f97316'),
  ('ransomware', '#dc2626'),
  ('botnet', '#a855f7'),
  ('malware-distribution', '#e11d48'),
  ('credential-theft', '#f59e0b'),
  ('scanning', '#3b82f6'),
  ('exploit', '#db2777'),
  ('apt', '#8b5cf6'),
  ('cryptominer', '#14b8a6'),
  ('tor-exit', '#64748b'),
  ('internal', '#22c55e');

-- ---------------------------------------------------------------------------
-- MITRE ATT&CK techniques (real technique ids and names)
-- ---------------------------------------------------------------------------
insert into public.mitre_techniques (id, name, tactics, url) values
  ('T1566', 'Phishing', array['Initial Access'], 'https://attack.mitre.org/techniques/T1566/'),
  ('T1190', 'Exploit Public-Facing Application', array['Initial Access'], 'https://attack.mitre.org/techniques/T1190/'),
  ('T1059', 'Command and Scripting Interpreter', array['Execution'], 'https://attack.mitre.org/techniques/T1059/'),
  ('T1204', 'User Execution', array['Execution'], 'https://attack.mitre.org/techniques/T1204/'),
  ('T1078', 'Valid Accounts', array['Defense Evasion', 'Persistence', 'Privilege Escalation', 'Initial Access'], 'https://attack.mitre.org/techniques/T1078/'),
  ('T1547', 'Boot or Logon Autostart Execution', array['Persistence', 'Privilege Escalation'], 'https://attack.mitre.org/techniques/T1547/'),
  ('T1055', 'Process Injection', array['Defense Evasion', 'Privilege Escalation'], 'https://attack.mitre.org/techniques/T1055/'),
  ('T1027', 'Obfuscated Files or Information', array['Defense Evasion'], 'https://attack.mitre.org/techniques/T1027/'),
  ('T1110', 'Brute Force', array['Credential Access'], 'https://attack.mitre.org/techniques/T1110/'),
  ('T1003', 'OS Credential Dumping', array['Credential Access'], 'https://attack.mitre.org/techniques/T1003/'),
  ('T1021', 'Remote Services', array['Lateral Movement'], 'https://attack.mitre.org/techniques/T1021/'),
  ('T1071', 'Application Layer Protocol', array['Command and Control'], 'https://attack.mitre.org/techniques/T1071/'),
  ('T1105', 'Ingress Tool Transfer', array['Command and Control'], 'https://attack.mitre.org/techniques/T1105/'),
  ('T1041', 'Exfiltration Over C2 Channel', array['Exfiltration'], 'https://attack.mitre.org/techniques/T1041/'),
  ('T1486', 'Data Encrypted for Impact', array['Impact'], 'https://attack.mitre.org/techniques/T1486/');

-- ---------------------------------------------------------------------------
-- Indicators
-- ---------------------------------------------------------------------------
insert into public.indicators
  (type, value, severity, verdict, confidence, status, source, description, first_seen, last_seen, origin)
select
  v.type::public.indicator_type, v.value, v.severity::public.severity, v.verdict::public.verdict,
  v.confidence, v.status::public.indicator_status, 'demo-seed', 'Demo data. ' || v.description,
  now() - make_interval(days => v.first_days), now() - make_interval(days => v.last_days), 'demo'
from (values
  -- IPv4 (RFC 5737 documentation ranges)
  ('ipv4', '198.51.100.23', 'critical', 'malicious', 92, 'active', 'Command-and-control server in the Harbor Lights scenario.', 40, 1),
  ('ipv4', '198.51.100.77', 'high', 'malicious', 85, 'active', 'Credential-stuffing source against a VPN portal.', 25, 1),
  ('ipv4', '203.0.113.45', 'high', 'malicious', 80, 'active', 'Web shell upload attempts.', 18, 3),
  ('ipv4', '203.0.113.9', 'medium', 'suspicious', 60, 'active', 'Broad port scanning activity.', 15, 2),
  ('ipv4', '192.0.2.150', 'medium', 'suspicious', 55, 'active', 'Sign-ins from a Tor exit node.', 30, 4),
  ('ipv4', '192.0.2.10', 'info', 'benign', 90, 'whitelisted', 'Internal vulnerability scanner.', 200, 1),
  ('ipv4', '198.51.100.200', 'medium', 'malicious', 70, 'active', 'Hosts a malware download site.', 20, 6),
  ('ipv4', '203.0.113.190', 'low', 'unknown', 30, 'under_review', 'Single unexplained outbound connection.', 5, 5),
  ('ipv4', '192.0.2.66', 'high', 'malicious', 88, 'active', 'Regular beaconing interval observed.', 35, 2),
  ('ipv4', '203.0.113.250', 'low', 'suspicious', 45, 'active', 'Repeated failed SSH logins.', 12, 8),
  -- IPv6 (RFC 3849 documentation range)
  ('ipv6', '2001:db8:bad:1::5', 'high', 'malicious', 75, 'active', 'Command-and-control endpoint reachable over IPv6.', 22, 2),
  ('ipv6', '2001:db8:cafe::2', 'medium', 'suspicious', 50, 'active', 'Unusual outbound IPv6 traffic.', 9, 3),
  -- Domains (reserved .example / .test TLDs)
  ('domain', 'login-secure-update.example', 'high', 'malicious', 90, 'active', 'Credential-harvesting page impersonating a login portal.', 30, 1),
  ('domain', 'cdn-assets-delivery.example', 'medium', 'suspicious', 60, 'active', 'Newly registered domain serving obfuscated scripts.', 14, 2),
  ('domain', 'paper-lantern-mail.example', 'critical', 'malicious', 93, 'active', 'Sender domain of the Paper Lantern phishing wave.', 55, 1),
  ('domain', 'update-service-check.test', 'high', 'malicious', 82, 'active', 'Fake software-update domain.', 28, 5),
  ('domain', 'harbor-lights-c2.example', 'critical', 'malicious', 95, 'active', 'Command-and-control domain in the Harbor Lights scenario.', 40, 1),
  ('domain', 'static.trusted-cdn.example', 'info', 'benign', 85, 'whitelisted', 'Approved content-delivery domain.', 300, 1),
  ('domain', 'invoice-download.example', 'high', 'malicious', 78, 'active', 'Serves malicious invoice archives.', 21, 2),
  ('domain', 'wintr-ledger-drop.example', 'medium', 'malicious', 65, 'expired', 'Payload drop site from the concluded Winter Ledger scenario.', 190, 125),
  ('domain', 'copper-thread-relay.test', 'medium', 'suspicious', 58, 'active', 'Relay domain from the dormant Copper Thread scenario.', 280, 95),
  -- URLs
  ('url', 'https://login-secure-update.example/account/verify?session=demo', 'high', 'malicious', 88, 'active', 'Phishing landing page.', 29, 1),
  ('url', 'http://invoice-download.example/files/invoice_2026.zip', 'high', 'malicious', 84, 'active', 'Malicious archive download.', 20, 2),
  ('url', 'https://paper-lantern-mail.example/track/open.gif', 'medium', 'suspicious', 62, 'active', 'Email tracking pixel from the phishing wave.', 50, 2),
  ('url', 'http://198.51.100.23/gate.php', 'critical', 'malicious', 91, 'active', 'Loader check-in endpoint.', 38, 1),
  ('url', 'https://harbor-lights-c2.example/api/v2/poll', 'critical', 'malicious', 94, 'active', 'Command polling endpoint.', 39, 1),
  ('url', 'https://cdn-assets-delivery.example/js/loader.min.js', 'medium', 'suspicious', 58, 'active', 'Obfuscated JavaScript loader.', 13, 2),
  -- Email addresses
  ('email', 'billing-alerts@login-secure-update.example', 'high', 'malicious', 80, 'active', 'Phishing sender address.', 27, 2),
  ('email', 'hr-notice@paper-lantern-mail.example', 'high', 'malicious', 85, 'active', 'Sender of the malicious-attachment emails.', 52, 3),
  ('email', 'helpdesk@invoice-download.example', 'medium', 'suspicious', 60, 'active', 'Sender of unsolicited invoice emails.', 19, 4),
  -- CVEs
  ('cve', 'CVE-2021-44228', 'critical', 'unknown', 95, 'active', 'Exploit pattern seen in web request headers.', 60, 1),
  ('cve', 'CVE-2022-22965', 'critical', 'unknown', 90, 'active', 'Unpatched Spring Framework instance identified.', 90, 10),
  ('cve', 'CVE-2021-34527', 'high', 'unknown', 85, 'under_review', 'Print Spooler exposure on a server segment.', 45, 15)
) as v (type, value, severity, verdict, confidence, status, description, first_days, last_days);

-- File hashes: digests of made-up strings, not real malware samples.
insert into public.indicators
  (type, value, severity, verdict, confidence, status, source, description, first_seen, last_seen, origin)
values
  ('sha256', pg_temp.sha256_of(1), 'critical', 'malicious', 94, 'active', 'demo-seed', 'Demo data. Loader dropper sample.', now() - interval '35 days', now() - interval '1 day', 'demo'),
  ('sha256', pg_temp.sha256_of(2), 'critical', 'malicious', 96, 'active', 'demo-seed', 'Demo data. Ransomware payload sample.', now() - interval '42 days', now() - interval '2 days', 'demo'),
  ('sha256', pg_temp.sha256_of(3), 'high', 'malicious', 82, 'active', 'demo-seed', 'Demo data. Backdoor implant sample.', now() - interval '70 days', now() - interval '12 days', 'demo'),
  ('sha256', pg_temp.sha256_of(4), 'medium', 'suspicious', 55, 'under_review', 'demo-seed', 'Demo data. Packed executable awaiting analysis.', now() - interval '6 days', now() - interval '5 days', 'demo'),
  ('sha256', pg_temp.sha256_of(5), 'high', 'malicious', 87, 'active', 'demo-seed', 'Demo data. Credential stealer sample.', now() - interval '25 days', now() - interval '4 days', 'demo'),
  ('md5', md5('arcradar-demo-sample-6'), 'high', 'malicious', 80, 'active', 'demo-seed', 'Demo data. Web shell sample.', now() - interval '18 days', now() - interval '3 days', 'demo'),
  ('sha1', encode(extensions.digest('arcradar-demo-sample-7', 'sha1'), 'hex'), 'medium', 'suspicious', 50, 'active', 'demo-seed', 'Demo data. Script dropper sample.', now() - interval '11 days', now() - interval '9 days', 'demo'),
  ('md5', md5('arcradar-demo-sample-8'), 'info', 'benign', 90, 'whitelisted', 'demo-seed', 'Demo data. Approved internal tool.', now() - interval '250 days', now() - interval '20 days', 'demo');

insert into public.indicator_tags (indicator_id, tag_id) values
  (pg_temp.ind('198.51.100.23'), pg_temp.tag('c2')),
  (pg_temp.ind('198.51.100.77'), pg_temp.tag('credential-theft')),
  (pg_temp.ind('203.0.113.45'), pg_temp.tag('exploit')),
  (pg_temp.ind('203.0.113.9'), pg_temp.tag('scanning')),
  (pg_temp.ind('192.0.2.150'), pg_temp.tag('tor-exit')),
  (pg_temp.ind('192.0.2.10'), pg_temp.tag('internal')),
  (pg_temp.ind('198.51.100.200'), pg_temp.tag('malware-distribution')),
  (pg_temp.ind('192.0.2.66'), pg_temp.tag('c2')),
  (pg_temp.ind('2001:db8:bad:1::5'), pg_temp.tag('c2')),
  (pg_temp.ind('login-secure-update.example'), pg_temp.tag('phishing')),
  (pg_temp.ind('login-secure-update.example'), pg_temp.tag('credential-theft')),
  (pg_temp.ind('paper-lantern-mail.example'), pg_temp.tag('phishing')),
  (pg_temp.ind('paper-lantern-mail.example'), pg_temp.tag('apt')),
  (pg_temp.ind('harbor-lights-c2.example'), pg_temp.tag('c2')),
  (pg_temp.ind('invoice-download.example'), pg_temp.tag('malware-distribution')),
  (pg_temp.ind('invoice-download.example'), pg_temp.tag('phishing')),
  (pg_temp.ind('wintr-ledger-drop.example'), pg_temp.tag('ransomware')),
  (pg_temp.ind('static.trusted-cdn.example'), pg_temp.tag('internal')),
  (pg_temp.ind('http://198.51.100.23/gate.php'), pg_temp.tag('c2')),
  (pg_temp.ind('https://harbor-lights-c2.example/api/v2/poll'), pg_temp.tag('c2')),
  (pg_temp.ind(pg_temp.sha256_of(1)), pg_temp.tag('malware-distribution')),
  (pg_temp.ind(pg_temp.sha256_of(2)), pg_temp.tag('ransomware')),
  (pg_temp.ind(pg_temp.sha256_of(3)), pg_temp.tag('apt')),
  (pg_temp.ind(pg_temp.sha256_of(5)), pg_temp.tag('credential-theft')),
  (pg_temp.ind('CVE-2021-44228'), pg_temp.tag('exploit')),
  (pg_temp.ind('CVE-2022-22965'), pg_temp.tag('exploit'));

insert into public.indicator_relationships (source_indicator_id, target_indicator_id, relationship) values
  (pg_temp.ind('harbor-lights-c2.example'), pg_temp.ind('198.51.100.23'), 'resolves_to'),
  (pg_temp.ind('login-secure-update.example'), pg_temp.ind('198.51.100.77'), 'resolves_to'),
  (pg_temp.ind('invoice-download.example'), pg_temp.ind('198.51.100.200'), 'resolves_to'),
  (pg_temp.ind('http://198.51.100.23/gate.php'), pg_temp.ind('198.51.100.23'), 'hosted_on'),
  (pg_temp.ind('https://harbor-lights-c2.example/api/v2/poll'), pg_temp.ind('harbor-lights-c2.example'), 'hosted_on'),
  (pg_temp.ind(pg_temp.sha256_of(1)), pg_temp.ind('http://198.51.100.23/gate.php'), 'communicates_with'),
  (pg_temp.ind(pg_temp.sha256_of(3)), pg_temp.ind('192.0.2.66'), 'communicates_with'),
  (pg_temp.ind('http://invoice-download.example/files/invoice_2026.zip'), pg_temp.ind(pg_temp.sha256_of(1)), 'downloads');

-- ---------------------------------------------------------------------------
-- Vulnerabilities (short summaries of public CVEs; verify against NVD)
-- ---------------------------------------------------------------------------
insert into public.vulnerabilities
  (cve_id, title, description, cvss_score, cvss_vector, cvss_version, severity, exploit_status,
   remediation, reference_urls, published_at, origin)
select
  v.cve_id, v.title, 'Demo data. Sample summary of a publicly documented vulnerability; verify details in NVD. ' || v.summary,
  v.score, v.vector, '3.1', v.severity::public.severity, v.exploit::public.exploit_status,
  v.remediation, array['https://nvd.nist.gov/vuln/detail/' || v.cve_id], v.published::timestamptz, 'demo'
from (values
  ('CVE-2021-44228', 'Apache Log4j2 JNDI remote code execution (Log4Shell)', 'Crafted log messages can trigger remote code loading through JNDI lookups.', 10.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 'critical', 'exploited_in_wild', 'Upgrade Log4j2 to a fixed release and remove JndiLookup where upgrade is not possible.', '2021-12-10'),
  ('CVE-2014-0160', 'OpenSSL TLS heartbeat information disclosure (Heartbleed)', 'Missing bounds check in the heartbeat extension can disclose process memory.', 7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 'high', 'exploited_in_wild', 'Upgrade OpenSSL and rotate keys and credentials that may have been exposed.', '2014-04-07'),
  ('CVE-2017-0144', 'Microsoft SMBv1 remote code execution (EternalBlue)', 'Specially crafted SMBv1 packets allow remote code execution.', 8.1, 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H', 'high', 'exploited_in_wild', 'Apply the MS17-010 update and disable SMBv1.', '2017-03-16'),
  ('CVE-2021-34527', 'Windows Print Spooler remote code execution (PrintNightmare)', 'Improper privilege handling in the Print Spooler service allows code execution.', 8.8, 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 'high', 'exploited_in_wild', 'Apply Microsoft security updates and disable the Print Spooler on systems that do not need it.', '2021-07-02'),
  ('CVE-2022-22965', 'Spring Framework remote code execution (Spring4Shell)', 'Data binding on JDK 9+ can allow remote code execution in some deployments.', 9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'critical', 'exploited_in_wild', 'Upgrade Spring Framework to a fixed release.', '2022-04-01'),
  ('CVE-2023-4863', 'libwebp heap buffer overflow', 'Processing a crafted WebP image can overflow a heap buffer.', 8.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', 'high', 'exploited_in_wild', 'Update libwebp and applications that bundle it.', '2023-09-12'),
  ('CVE-2021-26855', 'Microsoft Exchange Server request forgery (ProxyLogon)', 'Server-side request forgery in Exchange, chainable to code execution.', 9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'critical', 'exploited_in_wild', 'Apply the March 2021 Exchange security updates.', '2021-03-03'),
  ('CVE-2019-0708', 'Remote Desktop Services remote code execution (BlueKeep)', 'Pre-authentication flaw in Remote Desktop Services allows remote code execution.', 9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'critical', 'poc_available', 'Apply Microsoft updates and enable Network Level Authentication.', '2019-05-16'),
  ('CVE-2020-1472', 'Netlogon elevation of privilege (Zerologon)', 'Weak cryptography in the Netlogon protocol allows domain controller compromise.', 10.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 'critical', 'exploited_in_wild', 'Apply Microsoft updates and enforce secure RPC for Netlogon.', '2020-08-17'),
  ('CVE-2022-0847', 'Linux kernel pipe buffer overwrite (Dirty Pipe)', 'A flaw in pipe buffer handling allows overwriting data in read-only files.', 7.8, 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 'high', 'poc_available', 'Update the Linux kernel to a fixed version.', '2022-03-10'),
  ('CVE-2021-4034', 'Polkit pkexec local privilege escalation (PwnKit)', 'pkexec mishandles its arguments, allowing local privilege escalation.', 7.8, 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 'high', 'poc_available', 'Install distribution security updates for polkit.', '2022-01-28'),
  ('CVE-2023-23397', 'Microsoft Outlook elevation of privilege', 'A crafted message can cause the client to leak an NTLM hash without user interaction.', 9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'critical', 'exploited_in_wild', 'Apply the March 2023 Outlook update and restrict outbound NTLM.', '2023-03-14')
) as v (cve_id, title, summary, score, vector, severity, exploit, remediation, published);

insert into public.vulnerability_affected_products (vulnerability_id, vendor, product, affected_versions, fixed_version)
select v.id, a.vendor, a.product, a.affected, a.fixed
from (values
  ('CVE-2021-44228', 'Apache', 'Log4j2', '2.0-beta9 to 2.14.1', '2.15.0'),
  ('CVE-2014-0160', 'OpenSSL', 'OpenSSL', '1.0.1 to 1.0.1f', '1.0.1g'),
  ('CVE-2017-0144', 'Microsoft', 'Windows (SMBv1)', 'Unpatched supported Windows versions in March 2017', 'MS17-010'),
  ('CVE-2021-34527', 'Microsoft', 'Windows Print Spooler', 'Unpatched Windows versions before July 2021', 'July 2021 updates'),
  ('CVE-2022-22965', 'VMware', 'Spring Framework', '5.3.0 to 5.3.17 and 5.2.0 to 5.2.19', '5.3.18 / 5.2.20'),
  ('CVE-2023-4863', 'Google', 'libwebp', 'Before 1.3.2', '1.3.2'),
  ('CVE-2021-26855', 'Microsoft', 'Exchange Server 2013/2016/2019', 'Unpatched before March 2021', 'March 2021 updates'),
  ('CVE-2019-0708', 'Microsoft', 'Remote Desktop Services', 'Windows 7, Server 2008 and Server 2008 R2 unpatched', 'May 2019 updates'),
  ('CVE-2020-1472', 'Microsoft', 'Netlogon', 'Unpatched Windows Server versions before August 2020', 'August 2020 updates'),
  ('CVE-2022-0847', 'Linux', 'Linux kernel', '5.8 up to 5.16.10', '5.16.11 / 5.15.25 / 5.10.102'),
  ('CVE-2021-4034', 'Polkit', 'pkexec', 'All versions before the January 2022 fix', 'Distribution security updates'),
  ('CVE-2023-23397', 'Microsoft', 'Outlook for Windows', 'Unpatched before March 2023', 'March 2023 update')
) as a (cve_id, vendor, product, affected, fixed)
join public.vulnerabilities v on v.cve_id = a.cve_id;

-- ---------------------------------------------------------------------------
-- Events
-- ---------------------------------------------------------------------------
insert into public.events (event_type, title, description, severity, source, indicator_id, payload, occurred_at, origin)
select
  e.event_type,
  initcap(replace(e.event_type, '_', ' ')) || ' involving ' || i.value,
  'Demo data. Sample security event generated by the seed script.',
  (array['info', 'low', 'medium', 'high', 'critical']::public.severity[])[1 + (g * 7) % 5],
  (array['demo-firewall', 'demo-dns-resolver', 'demo-edr', 'demo-mail-gateway', 'demo-ids'])[1 + g % 5],
  i.id,
  jsonb_build_object('sequence', g, 'demo', true),
  now() - make_interval(hours => g * 9),
  'demo'
from generate_series(1, 30) as g
cross join lateral (
  select (array['firewall_block', 'dns_query', 'login_failed', 'malware_detected', 'email_phish_reported', 'ids_signature_match'])[1 + g % 6] as event_type
) e
cross join lateral (
  select id, value from public.indicators
  where origin = 'demo' and type in ('ipv4', 'domain', 'url', 'sha256')
  order by value
  offset (g * 3) % 25
  limit 1
) i;

-- ---------------------------------------------------------------------------
-- Alerts
-- ---------------------------------------------------------------------------
insert into public.alerts
  (title, description, severity, source, status, indicator_id, assigned_to,
   created_at, acknowledged_at, resolved_at, origin)
select
  a.title, 'Demo data. Sample alert generated by the seed script.', a.severity::public.severity, a.source,
  a.status::public.alert_status,
  case when a.indicator is null then null else pg_temp.ind(a.indicator) end,
  case when a.assigned then 'aaaaaaaa-0000-4000-8000-000000000002'::uuid end,
  now() - make_interval(hours => a.created_hours),
  case when a.ack_min is null then null else now() - make_interval(hours => a.created_hours) + make_interval(mins => a.ack_min) end,
  case when a.resolved_min is null then null else now() - make_interval(hours => a.created_hours) + make_interval(mins => a.resolved_min) end,
  'demo'
from (values
  ('C2 beacon to harbor-lights-c2.example', 'critical', 'demo-edr', 'investigating', 'harbor-lights-c2.example', true, 30, 15, null::int),
  ('Outbound connection to known malicious IP 198.51.100.23', 'critical', 'demo-firewall', 'investigating', '198.51.100.23', true, 28, 10, null),
  ('Phishing URL clicked by multiple users', 'high', 'demo-mail-gateway', 'acknowledged', 'https://login-secure-update.example/account/verify?session=demo', true, 20, 25, null),
  ('Suspicious PowerShell download cradle', 'high', 'demo-edr', 'new', pg_temp.sha256_of(1), false, 5, null, null),
  ('Credential stuffing against VPN portal', 'medium', 'demo-ids', 'new', '198.51.100.77', false, 12, null, null),
  ('DNS query to newly registered domain', 'medium', 'demo-dns-resolver', 'new', 'cdn-assets-delivery.example', false, 8, null, null),
  ('Ransomware file encryption pattern detected', 'critical', 'demo-edr', 'investigating', pg_temp.sha256_of(2), true, 40, 5, null),
  ('Web shell upload attempt blocked', 'high', 'demo-waf', 'resolved', '203.0.113.45', true, 70, 20, 300),
  ('Port scan from external host', 'low', 'demo-firewall', 'false_positive', '203.0.113.9', false, 50, 60, 90),
  ('Malicious attachment quarantined', 'high', 'demo-mail-gateway', 'resolved', 'hr-notice@paper-lantern-mail.example', true, 96, 12, 180),
  ('Exploit attempt: Log4Shell pattern in request headers', 'critical', 'demo-waf', 'acknowledged', 'CVE-2021-44228', true, 6, 8, null),
  ('Impossible travel sign-in', 'medium', 'demo-idp', 'new', null, false, 3, null, null),
  ('Outdated software with exploited-in-the-wild CVE', 'medium', 'demo-scanner', 'acknowledged', 'CVE-2022-22965', false, 60, 200, null),
  ('Beaconing interval detected to 192.0.2.66', 'high', 'demo-ids', 'resolved', '192.0.2.66', true, 120, 30, 720),
  ('Suspicious login from Tor exit node', 'low', 'demo-idp', 'false_positive', '192.0.2.150', false, 150, 30, 45)
) as a (title, severity, source, status, indicator, assigned, created_hours, ack_min, resolved_min);

-- ---------------------------------------------------------------------------
-- Assets: the fictional machines some of the demo events and alerts came from
-- ---------------------------------------------------------------------------
insert into public.assets (source, external_id, name, ip_address, os, origin, first_seen, last_seen) values
  ('demo-edr', 'DEMO-001', 'DEMO-WIN10-01', '192.0.2.21', 'Windows 10', 'demo', now() - interval '60 days', now() - interval '2 hours'),
  ('demo-edr', 'DEMO-002', 'DEMO-FILESRV-01', '192.0.2.22', 'Windows Server 2019', 'demo', now() - interval '200 days', now() - interval '40 hours'),
  ('demo-waf', 'DEMO-003', 'DEMO-WEB-01', '192.0.2.23', 'Ubuntu 22.04', 'demo', now() - interval '300 days', now() - interval '6 hours'),
  ('demo-mail-gateway', 'DEMO-004', 'DEMO-MAILGW-01', '192.0.2.24', 'Linux', 'demo', now() - interval '250 days', now() - interval '20 hours');

update public.events e set asset_id = a.id
  from public.assets a
  where e.origin = 'demo' and e.source = 'demo-edr' and a.external_id = 'DEMO-001';

update public.events e set asset_id = a.id
  from public.assets a
  where e.origin = 'demo' and e.source = 'demo-mail-gateway' and a.external_id = 'DEMO-004';

update public.alerts al set asset_id = a.id
  from public.assets a
  where al.origin = 'demo' and al.source = 'demo-edr' and al.title like 'Ransomware%' and a.external_id = 'DEMO-002';

update public.alerts al set asset_id = a.id
  from public.assets a
  where al.origin = 'demo' and al.source = 'demo-edr' and al.title not like 'Ransomware%' and a.external_id = 'DEMO-001';

update public.alerts al set asset_id = a.id
  from public.assets a
  where al.origin = 'demo' and al.source = 'demo-waf' and a.external_id = 'DEMO-003';

update public.alerts al set asset_id = a.id
  from public.assets a
  where al.origin = 'demo' and al.source = 'demo-mail-gateway' and a.external_id = 'DEMO-004';

-- ---------------------------------------------------------------------------
-- Investigations, notes, evidence and links
-- ---------------------------------------------------------------------------
insert into public.investigations
  (title, description, status, priority, analyst_id, closed_at, created_at, origin)
values
  ('Harbor Lights C2 infrastructure', 'Demo data. Map the command-and-control infrastructure seen in the Harbor Lights scenario.', 'investigating', 'critical', 'aaaaaaaa-0000-4000-8000-000000000002', null, now() - interval '36 hours', 'demo'),
  ('Paper Lantern phishing wave', 'Demo data. Scope the credential-phishing emails and affected mailboxes.', 'investigating', 'high', 'aaaaaaaa-0000-4000-8000-000000000002', null, now() - interval '100 hours', 'demo'),
  ('EmberLock ransomware on file server', 'Demo data. Contain and scope a ransomware infection on a file server.', 'contained', 'critical', 'aaaaaaaa-0000-4000-8000-000000000002', null, now() - interval '44 hours', 'demo'),
  ('Web shell upload on public site', 'Demo data. Review a blocked web shell upload attempt.', 'resolved', 'medium', 'aaaaaaaa-0000-4000-8000-000000000002', null, now() - interval '80 hours', 'demo'),
  ('Log4Shell exposure review', 'Demo data. Identify internal services that may be exposed to CVE-2021-44228.', 'open', 'high', null, null, now() - interval '8 hours', 'demo'),
  ('Outdated Spring Framework instances', 'Demo data. Inventory and patch vulnerable Spring Framework deployments.', 'closed', 'low', 'aaaaaaaa-0000-4000-8000-000000000002', now() - interval '150 hours', now() - interval '200 hours', 'demo');

insert into public.investigation_indicators (investigation_id, indicator_id) values
  (pg_temp.inv('Harbor Lights C2 infrastructure'), pg_temp.ind('198.51.100.23')),
  (pg_temp.inv('Harbor Lights C2 infrastructure'), pg_temp.ind('harbor-lights-c2.example')),
  (pg_temp.inv('Harbor Lights C2 infrastructure'), pg_temp.ind('https://harbor-lights-c2.example/api/v2/poll')),
  (pg_temp.inv('Harbor Lights C2 infrastructure'), pg_temp.ind(pg_temp.sha256_of(1))),
  (pg_temp.inv('Paper Lantern phishing wave'), pg_temp.ind('paper-lantern-mail.example')),
  (pg_temp.inv('Paper Lantern phishing wave'), pg_temp.ind('hr-notice@paper-lantern-mail.example')),
  (pg_temp.inv('Paper Lantern phishing wave'), pg_temp.ind('login-secure-update.example')),
  (pg_temp.inv('EmberLock ransomware on file server'), pg_temp.ind(pg_temp.sha256_of(2))),
  (pg_temp.inv('EmberLock ransomware on file server'), pg_temp.ind('wintr-ledger-drop.example')),
  (pg_temp.inv('Web shell upload on public site'), pg_temp.ind('203.0.113.45')),
  (pg_temp.inv('Web shell upload on public site'), pg_temp.ind(md5('arcradar-demo-sample-6'))),
  (pg_temp.inv('Log4Shell exposure review'), pg_temp.ind('CVE-2021-44228')),
  (pg_temp.inv('Outdated Spring Framework instances'), pg_temp.ind('CVE-2022-22965'));

insert into public.investigation_alerts (investigation_id, alert_id) values
  (pg_temp.inv('Harbor Lights C2 infrastructure'), pg_temp.alrt('C2 beacon to harbor-lights-c2.example')),
  (pg_temp.inv('Harbor Lights C2 infrastructure'), pg_temp.alrt('Outbound connection to known malicious IP 198.51.100.23')),
  (pg_temp.inv('Paper Lantern phishing wave'), pg_temp.alrt('Phishing URL clicked by multiple users')),
  (pg_temp.inv('Paper Lantern phishing wave'), pg_temp.alrt('Malicious attachment quarantined')),
  (pg_temp.inv('EmberLock ransomware on file server'), pg_temp.alrt('Ransomware file encryption pattern detected')),
  (pg_temp.inv('Web shell upload on public site'), pg_temp.alrt('Web shell upload attempt blocked')),
  (pg_temp.inv('Log4Shell exposure review'), pg_temp.alrt('Exploit attempt: Log4Shell pattern in request headers')),
  (pg_temp.inv('Outdated Spring Framework instances'), pg_temp.alrt('Outdated software with exploited-in-the-wild CVE'));

-- The links were added shortly after each investigation was opened (this feeds its timeline).
update public.investigation_indicators ii set added_at = i.created_at + interval '20 minutes'
from public.investigations i where i.id = ii.investigation_id;
update public.investigation_alerts ia set added_at = i.created_at + interval '10 minutes'
from public.investigations i where i.id = ia.investigation_id;

insert into public.investigation_tags (investigation_id, tag_id) values
  (pg_temp.inv('Harbor Lights C2 infrastructure'), pg_temp.tag('c2')),
  (pg_temp.inv('Paper Lantern phishing wave'), pg_temp.tag('phishing')),
  (pg_temp.inv('EmberLock ransomware on file server'), pg_temp.tag('ransomware')),
  (pg_temp.inv('Web shell upload on public site'), pg_temp.tag('exploit')),
  (pg_temp.inv('Log4Shell exposure review'), pg_temp.tag('exploit'));

-- updated_at is set to created_at, so the demo notes do not look edited (the page marks a note as
-- edited when the two differ).
insert into public.investigation_notes (investigation_id, author_id, body, created_at, updated_at)
select v.inv, v.author, v.body, v.at, v.at
from (values
  (pg_temp.inv('Harbor Lights C2 infrastructure'), 'aaaaaaaa-0000-4000-8000-000000000002'::uuid, 'Demo data. The polling endpoint and the domain resolve to the same address; pivoting on the loader check-in URL next.', now() - interval '30 hours'),
  (pg_temp.inv('Harbor Lights C2 infrastructure'), 'aaaaaaaa-0000-4000-8000-000000000001'::uuid, 'Demo data. Blocked the domain at the DNS resolver; watch for fallback domains.', now() - interval '24 hours'),
  (pg_temp.inv('Paper Lantern phishing wave'), 'aaaaaaaa-0000-4000-8000-000000000002'::uuid, 'Demo data. Three users clicked the link; password resets issued.', now() - interval '90 hours'),
  (pg_temp.inv('EmberLock ransomware on file server'), 'aaaaaaaa-0000-4000-8000-000000000002'::uuid, 'Demo data. Host isolated from the network; restoring from the last clean backup.', now() - interval '40 hours'),
  (pg_temp.inv('Web shell upload on public site'), 'aaaaaaaa-0000-4000-8000-000000000002'::uuid, 'Demo data. Upload blocked by the WAF; no file reached the web root.', now() - interval '75 hours')
) as v(inv, author, body, at);

-- Status history, as the application records it (kind = 'system').
insert into public.investigation_notes (investigation_id, author_id, kind, body, created_at, updated_at)
select v.inv, v.author, 'system', v.body, v.at, v.at
from (values
  (pg_temp.inv('Harbor Lights C2 infrastructure'), 'aaaaaaaa-0000-4000-8000-000000000002'::uuid, 'Status changed from Open to Investigating. (Demo data)', now() - interval '35 hours'),
  (pg_temp.inv('Paper Lantern phishing wave'), 'aaaaaaaa-0000-4000-8000-000000000002'::uuid, 'Status changed from Open to Investigating. (Demo data)', now() - interval '98 hours'),
  (pg_temp.inv('EmberLock ransomware on file server'), 'aaaaaaaa-0000-4000-8000-000000000002'::uuid, 'Status changed from Open to Investigating. (Demo data)', now() - interval '43 hours'),
  (pg_temp.inv('EmberLock ransomware on file server'), 'aaaaaaaa-0000-4000-8000-000000000002'::uuid, 'Status changed from Investigating to Contained. (Demo data)', now() - interval '38 hours'),
  (pg_temp.inv('Web shell upload on public site'), 'aaaaaaaa-0000-4000-8000-000000000002'::uuid, 'Status changed from Open to Resolved. (Demo data)', now() - interval '70 hours'),
  (pg_temp.inv('Outdated Spring Framework instances'), 'aaaaaaaa-0000-4000-8000-000000000002'::uuid, 'Status changed from Open to Closed. (Demo data)', now() - interval '150 hours')
) as v(inv, author, body, at);

insert into public.investigation_evidence (investigation_id, title, location, description, added_by, created_at) values
  (pg_temp.inv('Harbor Lights C2 infrastructure'), 'Firewall log excerpt', 'demo://logs/firewall/2026-09-24', 'Demo data. Outbound sessions to the C2 address.', 'aaaaaaaa-0000-4000-8000-000000000002', now() - interval '29 hours'),
  (pg_temp.inv('Paper Lantern phishing wave'), 'Original phishing email', 'demo://mail/quarantine/msg-1042', 'Demo data. Message headers and body.', 'aaaaaaaa-0000-4000-8000-000000000002', now() - interval '95 hours'),
  (pg_temp.inv('EmberLock ransomware on file server'), 'EDR detection report', 'demo://edr/reports/1187', 'Demo data. Process tree and file activity.', 'aaaaaaaa-0000-4000-8000-000000000002', now() - interval '42 hours');
