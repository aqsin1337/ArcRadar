# ArcRadar: video təqdimat ssenarisi

Təxmini müddət: **10 dəqiqə**. Danışıq Azərbaycan dilindədir, ekrandakı adlar (Alerts, Investigations və s.)
ingiliscə qalır. Hər addımda **Et** (nə edirsən) və **De** (nə deyirsən) var.

> Canlı admin parolu bu faylda yazılmır (repo açıqdır). Onu özün bilirsən və videoda göz ikonunu basmırsan.

## Hazırlıq (yazıdan əvvəl, 10 dəqiqə)

1. VMware-də iki VM açıq olsun: Ubuntu **Wazuh Manager** (`192.168.218.10`) və **Windows 10** (`192.168.218.20`).
   Agent `WIN10-LAB` aktiv olmalıdır: Manager-də `sudo /var/ossec/bin/agent_control -l`.
2. Windows-da **Administrator CMD** hazır dursun.
3. Brauzerdə `arcradar.vercel.app` **çıxış edilmiş** vəziyyətdə açıq olsun (login göstərmək üçün). İkinci **inkoqnito** pəncərə də hazır olsun.
4. **Hücum əmrlərini bir dəfə sına** və alert-lərin gəldiyini gör. Sonra VM snapshot-u götür.
5. Bir Wazuh qaydasını videodan əvvəl GitHub-a göndər (Manager onu 10 dəqiqəyə çəkir).
6. Video hesabı (L1/L2 göstərmək üçün) lazımdırsa əvvəlcədən real e-poçtla aç, çünki Supabase-in daxili SMTP-si saatda cəmi 2 mail göndərir.
7. Ekran 1920x1080, brauzer zoom 100%, tünd tema, bildirişlər söndürülüb. `.env` fayllarını açma.
8. Hər səhifə üçün əvvəlcədən ayrı tab aç (Alerts, MITRE, IP intelligence, Detection rules, Settings, Audit log, GitHub repo).

## 1. Açılış: landing page (40 san)

**Et:** `arcradar.vercel.app` açılır. Yavaş aşağı sürüşdür: hero, pipeline, "Write a sentence. Get a Wazuh rule.", Engineering.

**De:** "Mən ArcRadar-ı təqdim edirəm. Bu, SIEM-i əvəz etmir, onun yanında işləyən incident response platformasıdır. Real
endpoint-dən gələn alert-ləri toplayır, zənginləşdirir, MITRE ATT&CK-ə uyğunlaşdırır, analitikə AI köməyi ilə triage
etdirir və işi bağlanana qədər izləyir. Heç nəyi öz-özünə icra etmir."

## 2. Giriş (40 san)

**Et:** **Sign in to the console** bas. Email `admin@arcradar.app`, parolu yaz (göz ikonunu basma). **Sign in**.

**De:** "Giriş rola əsaslanır. Mən administratoram. Sistemdə dörd rol var: Admin, SOC L2, SOC L1 və Viewer. Bunlara
sonra qayıdacağam."

## 3. Ümumi görünüş (40 san)

**Et:** **Overview** səhifəsinə bax. Sol menyunu göstər (Operations, Intelligence, Administration). Yuxarıdakı axtarışı göstər (`/` düyməsi).

**De:** "Menyu funksiyaya görə qruplaşıb. Başlıqlardakı say real say-dır, filtr ilə dəyişmir. Hər qeyd haradan gəldiyini
provenance etiketi ilə göstərir: External, Local və ya Demo."

## 4. Real hücum (2 dəqiqə)

**Et:** Windows VM-ə keç. **Administrator** CMD-də hücum zəncirini ardıcıl işlət. Hər addım MITRE matrisində ayrı xananı rəngləyir:

```
:: 1. Brute force (T1110): kilid ekranında 5-6 səhv parol yazmaq ən etibarlısıdır
for /L %i in (1,1,6) do net use \\127.0.0.1\IPC$ /user:administrator SehvParol%i

:: 2. Gizli hesab yaratmaq (T1098, Persistence)
net user demosvc P@ssw0rd-Demo1 /add

:: 3. Hesabın parolunu dəyişmək (T1098)
net user demosvc Yeni-P@ss-Demo2

:: 4. Təhlükəsizlik qrupu yaratmaq (T1484.001)
net localgroup demoteam /add

:: 5. Audit jurnalını silmək (T1070.004, Defense Evasion)
wevtutil cl Security

:: 6. Hesabı və qrupu silmək (T1531, Impact)
net user demosvc /delete
net localgroup demoteam /delete
```

**De (icra edərkən):** "Bu Windows 10 maşınıdır. İndi hücumçunun addımlarını təqlid edirəm: parol təxmin edir, gizli
hesab açır, parolunu dəyişir, qrup yaradır, audit jurnalını silir və izləri yox edir. Maşındakı Wazuh Agent hər
hadisəni Manager-ə göndərir."

## 5. Alert-lər (1 dəqiqə)

**Et:** ArcRadar-da **Telemetry** aç (Wazuh mənbəyi "Receiving"), sonra **Alerts**. Bir alert aç: severity, asset
`WIN10-LAB`, MITRE texnika, **Timeline**.

**De:** "Manager qayda ilə alert yaradıb HTTPS və hash-lənmiş, scope-lu API açarı ilə mənim platformama push etdi.
Gördüyünüz real hadisədir. Etiket **External** göstərir, yəni demo data deyil."

> Alert 2 dəqiqədə görünmürsə: Manager-də `tail -f /var/ossec/logs/integrations.log` ilə bax. Ehtiyat plan: 7-ci
> addıma keç və alert-i sonra göstər.

## 6. MITRE ATT&CK matrisi (30 san)

**Et:** **MITRE ATT&CK** səhifəsi. Rənglənmiş xanalara göstər, **Sub-techniques** düyməsini bas (T1070.004, T1484.001
görünür), T1110 xanasına klik et.

**De:** "Bu matris kataloq deyil. Yalnız mənim öz maşınımda baş verən texnikalar rənglənir, rəng ən yüksək severity-ni
göstərir. Klik edəndə arxasındakı alert-lərə keçirəm."

## 7. Threat intelligence (45 san)

**Et:** **IP intelligence** səhifəsi. Məlum zərərli Tor çıxış IP-si yaz (`185.220.101.4`) və **Look up** bas. VirusTotal,
AbuseIPDB və OTX cavabları görünür.

**De:** "Analitik istənilən IP-ni araşdıra bilər. Daxili ünvanlar heç vaxt xaricə göndərilmir, buna görə real hadisədəki
daxili IP üçün xarici sorğu getmədi. Bu, məqsədli dizayndır. Nəticə provenance etiketi ilə saxlanır."

## 8. AI analiz (1 dəqiqə)

**Et:** Audit jurnalı silinməsi alert-ini aç. **AI analysis** kartında threat summary və false-positive score işə sal.
Sonra **Workflow** düymələrini göstər: **Acknowledge**, **Start investigating**.

**De:** "AI yalnız tövsiyə verir. Cavab schema ilə yoxlanır, dəyişməz saxlanır, 'AI-generated, analyst-assisted' etiketi
ilə göstərilir və audit olunur. Response action-larını analitik əllə tamamlayır, sistem heç nə icra etmir."

## 9. Case management (1 dəqiqə)

**Et:** **Open an investigation** bas. Investigation səhifəsində AI checklist yarat, bir-iki maddəni işarələ, qeyd yaz.
Sonra **Reports** səhifəsindən yeni hesabat yarat.

**De:** "Investigation case faylıdır: qeydlər, sübutlar, yoxlama siyahısı və serverin yazdığı tarixçə. Hesabat həmin
anın dəyişməz snapshot-udur, çap edib PDF edə bilərəm."

## 10. Detection as code (1,5 dəqiqə)

**Et:** **Detection rules** → **Wazuh rules** → **Generate with AI**. Yaz: _"eyni IP-dən 5 dəqiqədə 5 uğursuz Windows
girişi"_. Yaranan XML-ə bax, **Send to GitHub** bas. GitHub repoda `arcradar_<id>.xml` faylını göstər.

**De:** "XML-i ArcRadar özü render edir, ona görə içində active response ola bilməz. Qayda GitHub-a commit olunur,
Manager onu özü çəkib `wazuh-analysisd -t` ilə test edir və yükləyir. ArcRadar Manager-ə heç vaxt qoşulmur."

> Manager-də dərhal göstərmək istəsən: `sudo /usr/local/sbin/arcradar-apply-rules`.

## 11. SOC rolları və hesab təsdiqi (1,5 dəqiqə)

**Et (inkoqnito pəncərə):** **Sign up** ilə hesab yarat. Giriş cəhdində "waiting for approval" mesajı görünür.

**Et (admin pəncərəsi):** **Settings** → sarı xəbərdarlıq ("accounts waiting for approval"). Rolu **SOC L1** seç, **Approve**
bas. Yeni hesabla daxil ol: yalnız alert triage edir, investigation aça bilmir. Sonra rolu **SOC L2** et və fərqi göstər.

**De:** "Rollar real SOC strukturuna uyğundur. L1 triage edir və eskalasiya edir, L2 araşdırır və case açır, Admin
idarə edir. Yeni hesab mən icazə verməyincə işləmir, rolu da mən təyin edirəm. Bu qayda verilənlər bazası
səviyyəsində tətbiq olunur, yəni Supabase-in açıq signup endpoint-i ilə də keçmək olmur."

**Sonra:** **Audit log** səhifəsini göstər: `user.approved`, giriş cəhdləri.

## 12. Yekun (45 san)

**Et:** GitHub repo səhifəsi (README, CI badge), sonra landing-in **Engineering** bölməsi.

**De:** "Hər cədvəldə row-level security, nonce-li CSP, paylaşılan rate limit, append-only audit log, 850-dən çox
unit test, SQL təhlükəsizlik testləri, Playwright E2E və əlçatanlıq yoxlaması var. Vercel və Supabase üzərində
işləyir. Növbəti addım Shuffle kimi SOAR ilə inteqrasiya olardı. Təşəkkür edirəm."

## Sual-cavab üçün qısa cavablar

- **Niyə SIEM deyil?** SIEM aşkarlayır. ArcRadar aşkarlanandan sonrakı işi (triage, case, cavab izləmə) idarə edir.
- **AI səhv etsə?** O yalnız tövsiyə verir, hər cavab insan tərəfindən yoxlanır, heç nə avtomatik icra olunmur.
- **Wazuh-a necə qoşulur?** Manager `<integration>` ilə HTTPS və hash-lənmiş, scope-lu API açarı ilə push edir.
  ArcRadar heç vaxt sensora qoşulmur.
- **Qaydaları kim yükləyir?** Manager özü GitHub-dan çəkir və yoxlayır. ArcRadar-ın Manager-ə girişi yoxdur.
- **Rollar necə təmin olunur?** Row-level security ilə verilənlər bazasında. Tətbiq yalnız sürətli ilkin yoxlamadır.
- **Nə əlavə edilə bilər?** Shuffle/SOAR inteqrasiyası (icazə ilə tipli response action-lar), canlı statistika.
