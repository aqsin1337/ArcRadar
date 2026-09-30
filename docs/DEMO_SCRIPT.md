# ArcRadar: video təqdimat ssenarisi

Təxmini müddət: **7-9 dəqiqə**. Danışıq Azərbaycan dilindədir, ekrandakı adlar (Alerts, Investigations və s.)
ingiliscə qalır. Hər addımda: **Nə göstərirsən**, **Nə deyirsən**.

## 0. Yazıdan əvvəl hazırlıq (15 dəqiqə)

1. VMware-də iki VM açıq olsun: Ubuntu **Wazuh Manager** (`192.168.218.10`) və **Windows 10** (`192.168.218.20`).
2. Yoxla ki, agent aktivdir: Manager-də `sudo /var/ossec/bin/agent_control -l` (agent `WIN10-LAB` **Active**).
3. Brauzerdə iki tab aç: `https://arcradar.vercel.app` (admin kimi girişli) və ikinci pəncərədə **inkoqnito**
   (yeni hesab açmaq üçün).
4. Windows VM-də bir CMD pəncərəsi hazır saxla (aşağıdakı hücum əmri üçün).
5. Bir dəfə "quru məşq" et: hücum əmrini işlət, alert-in 1-2 dəqiqəyə ArcRadar-da göründüyünü gör. Sonra videoya keç.
6. Ekran qətnaməsi 1920x1080, brauzer zoom 100%, tünd tema. Bildirişləri (Windows, Discord və s.) söndür.
7. Yazı zamanı gizli qalmalı: API açarları, Supabase/GitHub tokenləri. Integrations və API keys səhifələrində açar dəyərləri
   onsuz da göstərilmir, amma `.env` fayllarını açma.

## 1. Giriş (30 san)

**Göstər:** `arcradar.vercel.app` landing page. Yavaş aşağı sürüşdür: hero, pipeline, "Write a sentence. Get a Wazuh rule."

**De:** "ArcRadar SIEM-i əvəz etmir, onun yanında işləyir. Real endpoint-dən gələn alert-ləri toplayır, zənginləşdirir,
MITRE ATT&CK-ə uyğunlaşdırır, analitikə AI köməyi ilə triage etdirir və işi bağlanana qədər izləyir. Heç nəyi öz-özünə icra etmir."

## 2. Real hücum, real alert (2 dəqiqə): əsas an

**Göstər:** Windows VM. CMD-də 6 uğursuz giriş cəhdi:

```
for /L %i in (1,1,6) do net use \\127.0.0.1\IPC$ /user:administrator SehvParol%i
```

Sonra ArcRadar-a keç: **Telemetry** (Wazuh mənbəyi "Receiving") və **Alerts**. Alert 1-2 dəqiqəyə görünəcək
(Manager onu göndərir). Alert-i aç.

**De:** "Bu Windows 10 maşınında indicə uğursuz giriş cəhdləri etdim. Wazuh Agent bunu Manager-ə göndərdi, Manager qayda
ilə alert yaratdı və HTTPS ilə ArcRadar-a push etdi. Burada gördüyünüz real hadisədir, demo data deyil. Provenance etiketi
**External** göstərir."

Göstər: severity, asset `WIN10-LAB`, MITRE texnika (T1110), **Timeline**.

> Əgər alert 2 dəqiqədə görünmürsə: Manager-də `tail -f /var/ossec/logs/integrations.log` ilə bax. Ehtiyat plan:
> aşağıdakı 3-cü bölməyə keç və alert-i sonra göstər.

## 3. Threat intelligence araşdırması (1 dəqiqə)

**Göstər:** **IP intelligence** səhifəsi. Məlum zərərli Tor çıxış IP-si yaz (məsələn `185.220.101.4`) və Look up düyməsini bas.
VirusTotal, AbuseIPDB və OTX cavabları görünür.

**De:** "Analitik istənilən IP-ni araşdıra bilər. Daxili (private) ünvanlar heç vaxt xaricə göndərilmir, nəticələr də
provenance ilə yadda saxlanır. Real hadisədəki IP daxili olduğu üçün xarici sorğu getmədi, bu məqsədli dizayndır."

## 4. AI ilə triage (1 dəqiqə)

**Göstər:** alert səhifəsində **AI analysis** kartı: Threat summary, MITRE mapping, False-positive score, Response actions.
Birini işə sal (Groq cavab verir).

**De:** "AI yalnız tövsiyə verir. Cavab schema ilə yoxlanır, dəyişməz saxlanır, 'AI-generated · analyst-assisted' kimi
etiketlənir və audit olunur. Response action-ları analitik əllə tamamlayır, sistem heç nə icra etmir."

## 5. Case management (1 dəqiqə)

**Göstər:** alert-dən **Open an investigation**. Yoxlama siyahısı (AI checklist), qeyd əlavə et, status dəyiş.
Sonra **Reports** bölməsində hesabat yarat.

## 6. MITRE ATT&CK matrisi (30 san)

**Göstər:** **MITRE ATT&CK** səhifəsi. T1110 rənglənib. Klik et, arxasındakı alert-lərə keç.

**De:** "Matris kataloqu deyil, mənim öz maşınımda nə baş verdiyini göstərir."

## 7. Detection as code (1,5 dəqiqə)

**Göstər:** **Detection rules** → **Generate with AI**. Yaz: "eyni IP-dən 5 dəqiqədə 5 uğursuz Windows girişi".
XML-ə bax, **Send to GitHub**. GitHub repoda `arcradar_<id>.xml` faylını göstər.

**De:** "Qayda XML-ni ArcRadar özü render edir, ona görə içində active response ola bilməz. GitHub-a commit olunur, Manager
10 dəqiqədən bir öz-özünə çəkib `wazuh-analysisd -t` ilə yoxlayır və yükləyir. ArcRadar Manager-ə heç vaxt özü qoşulmur."

> Manager-də dərhal göstərmək istəsən: `sudo /usr/local/sbin/arcradar-apply-rules` işlət.

## 8. SOC rolları və hesab təsdiqi (1,5 dəqiqə)

**Göstər (inkoqnito pəncərə):** **Sign up** ilə yeni hesab yarat. Giriş cəhdində "waiting for approval" görünür.

**Sonra admin pəncərəsi:** **Settings** → yuxarıda "1 account waiting for approval". Rolu seç (**SOC L1**) və **Approve**.
Yeni hesabla giriş et: L1 yalnız alert triage edə bilir, investigation aça bilmir. **SOC L2** ilə fərqi göstər.

**De:** "Rollar real SOC strukturuna uyğundur: L1 triage edir və eskalasiya edir, L2 araşdırır və case açır, Admin idarə edir.
Yeni hesab mən icazə verməyincə giriş edə bilmir və rolu mən təyin edirəm. Bu qayda verilənlər bazası səviyyəsində
tətbiq olunur, yəni Supabase-in açıq signup endpoint-i ilə də keçmək olmur."

Sonra **Audit log** səhifəsini göstər: `user.approved`, giriş cəhdləri.

## 9. Mühəndislik və yekun (45 san)

**Göstər:** GitHub repo (README, CI badge). Sonra landing-in "Engineering" bölməsi.

**De:** "Hər cədvəldə row-level security, nonce-li CSP, paylaşılan rate limit, append-only audit log, 850+ unit test,
SQL təhlükəsizlik testləri, Playwright E2E və əlçatanlıq yoxlaması. Vercel və Supabase üzərində işləyir."

## Sual-cavab üçün qısa cavablar

- **Niyə SIEM deyil?** SIEM aşkarlayır. ArcRadar aşkarlanandan sonrakı işi (triage, case, cavab izləmə) idarə edir.
- **AI səhv etsə?** O yalnız tövsiyə verir, hər cavab insan tərəfindən yoxlanır, heç nə avtomatik icra olunmur.
- **Wazuh-a necə qoşulur?** Manager `<integration>` ilə HTTPS + hash-lənmiş, scope-lu API açarı ilə push edir. ArcRadar heç vaxt
  sensora qoşulmur.
- **Qaydaları kim yükləyir?** Manager özü GitHub-dan çəkir və yoxlayır. ArcRadar-ın Manager-ə girişi yoxdur.
- **Əlavə edilə biləcək:** Shuffle/SOAR inteqrasiyası (icazə ilə tipli response action-lar), landing üçün canlı statistika.
