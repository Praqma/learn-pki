# Setup PKI using Easy RSA

## Infrastructure:
* OS: CENTOS 7
* Node1: rootca.example.com (192.168.122.50)
* Node2: web-server.example.com (192.168.122.51)

## Install easy-rsa on the RootCA node:

```
[root@rootca ~]# yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
```

```
[root@rootca ~]# yum -y install openssl easy-rsa
```


```
[root@rootca ~]# cp /usr/share/easy-rsa/3.0.7/easyrsa /usr/local/bin/
``` 


```
[root@rootca ~]# mkdir ~/easy-rsa
```

Create the symlinks with the ln command:

```
[root@rootca ~]# ln -s /usr/share/easy-rsa/* ~/easy-rsa/
[root@rootca ~]# ls -l easy-rsa/
total 0
lrwxrwxrwx 1 root root 21 Jul 15 21:38 3 -> /usr/share/easy-rsa/3
lrwxrwxrwx 1 root root 23 Jul 15 21:38 3.0 -> /usr/share/easy-rsa/3.0
lrwxrwxrwx 1 root root 25 Jul 15 21:38 3.0.7 -> /usr/share/easy-rsa/3.0.7
[root@rootca ~]# 
```

Initialize the PKI inside the easy-rsa directory:

```
[root@rootca ~]# cd ~/easy-rsa

[root@rootca easy-rsa]# easyrsa init-pki

init-pki complete; you may now create a CA or requests.
Your newly created PKI dir is: /root/easy-rsa/pki


[root@rootca easy-rsa]# 
```

Verify:
```
[root@rootca easy-rsa]# ls -l
total 0
lrwxrwxrwx 1 root root 21 Jul 15 21:38 3 -> /usr/share/easy-rsa/3
lrwxrwxrwx 1 root root 23 Jul 15 21:38 3.0 -> /usr/share/easy-rsa/3.0
lrwxrwxrwx 1 root root 25 Jul 15 21:38 3.0.7 -> /usr/share/easy-rsa/3.0.7
drwx------ 4 root root 33 Jul 15 21:43 pki
[root@rootca easy-rsa]# 

```

Now, create the **private key** and **public certificate** for your CA.

## Create Certificate Authority (CA):
Before you can create your CA’s private key and certificate, you need to create and populate a file called `~/easy-rsa/vars` with some default values. 


```
[root@rootca easy-rsa]# cat > vars << EOF
set_var EASYRSA_REQ_COUNTRY    "NO"
set_var EASYRSA_REQ_PROVINCE   "Oslo"
set_var EASYRSA_REQ_CITY       "Oslo"
set_var EASYRSA_REQ_ORG        "Exemplary Organization"
set_var EASYRSA_REQ_EMAIL      "admin@example.com"
set_var EASYRSA_REQ_OU         "IT"
set_var EASYRSA_ALGO           "ec"
set_var EASYRSA_DIGEST         "sha512" 
EOF
```


You need a file under pki. If you don't do this, you will receive an error.
```
[root@rootca easy-rsa]# cp /usr/share/easy-rsa/3.0.7/openssl-easyrsa.cnf pki/
```

Or, you can add the following line to the vars file:

```
set_var  EASYRSA_SSL_CONF "$EASYRSA/openssl-easyrsa.cnf"
```



Now, run the `easyrsa` command again, with the `build-ca` option to create a key-pair for your CA:

```
[root@rootca easy-rsa]# easyrsa build-ca
WARNING: can't open config file: /root/easy-rsa/pki/safessl-easyrsa.cnf
WARNING: can't open config file: /root/easy-rsa/pki/safessl-easyrsa.cnf
Using SSL: openssl OpenSSL 1.0.2k-fips  26 Jan 2017

Enter New CA Key Passphrase: 
Re-Enter New CA Key Passphrase: 
WARNING: can't open config file: /root/easy-rsa/pki/safessl-easyrsa.cnf
Generating RSA private key, 2048 bit long modulus
.....................+++
........................................................+++
e is 65537 (0x10001)
WARNING: can't open config file: /root/easy-rsa/pki/safessl-easyrsa.cnf
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Common Name (eg: your user, host, or server name) [Easy-RSA CA]:rootca.example.com

CA creation complete and you may now import and sign cert requests.
Your new CA certificate file for publishing is at:
/root/easy-rsa/pki/ca.crt


[root@rootca easy-rsa]# 
```


**Note:** Passphrase is "F3d0ra@"

You now have two important files - `~/easy-rsa/pki/ca.crt` and `~/easy-rsa/pki/private/ca.key` - which make up the public and private components of a Certificate Authority.


* `ca.crt` is the CA’s public certificate file. Users, servers, and clients will use this certificate to verify that they are part of the same web of trust. Every user and server that uses your CA will need to have a copy of this file. All parties will rely on the public certificate to ensure that someone is not impersonating a system and performing a Man-in-the-middle attack.

* `ca.key` is the private key that the CA uses to sign certificates for servers and clients. If an attacker gains access to your CA and, in turn, your `ca.key` file, you will need to destroy your CA. This is why your `ca.key` file should only be on your CA machine and that, ideally, your CA machine should be kept offline when not signing certificate requests as an extra security measure.

With that, your CA is in place and it is ready to be used to sign certificate requests, and to revoke certificates.

## Distribute you CA's certificate:

At this point, your CA is configured and ready to act as a **root of trust** for any systems in the network. 

You can add the CA’s certificate to your OpenVPN servers, web servers, mail servers, and so on. 

Any user or server that needs to verify the identity of another user or server in your network should have a copy of the RootCA's `ca.crt` file imported into their operating system’s certificate store.

Use any file transfer utilities to copy the CA's `ca.crt` file to other systems.

The `ca.crt` file looks like this:
```
[root@rootca easy-rsa]# cat ~/easy-rsa/pki/ca.crt
-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIJAKWOfHtXqWxfMA0GCSqGSIb3DQEBCwUAMB0xGzAZBgNV
BAMMEnJvb3RjYS5leGFtcGxlLmNvbTAeFw0yMDA3MTUyMDEzNTlaFw0zMDA3MTMy
MDEzNTlaMB0xGzAZBgNVBAMMEnJvb3RjYS5leGFtcGxlLmNvbTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMQ8dfW3rbJ9BmjYbY6hEbnH9AsYjGx7h+HN
Ia1WioxLI3usT4N5NarNmEiA5AocFHWh79V2patluv34ulCDVMgMRbyEIzmNiPaL
5wBCMhaiZOn+BPxr7yM3w+MnqIz1s538HHdzlhqlWOogTmsNNJKMjCfzT9CtXLNd
OXUh2uc8yQhqJYv94wa7sVDC76yJXQE9Dvwaoo7SCbEJb/o21HphsomsxcnJpHAZ
QtOO75060QnxFHaKjZuJ6+TJ/5+frfs+hVYD6lwzNcljz. . . 
jrTMFVSOmilmEVJLGv/NY66Bqbo2MUMp69JPbLCvq+MbljCXr8sgRxSCpz2CaKEN
Tpn4DC7ebfzUbXGEHrGi2XtfHNoYRYK1yh1+7/Eg+sw5QT2cGQbc2MTlkJVJH2fd
dSaAa6YEJN2o03j1TWIDZnXqYW0lJtReQim5g8A72MVfl0yoxBRxtuo/6um46TkP
JsO8hVrpqi2KbuaSjOLEJleDMX83JoosRfWhc6eLtBEDTE+yvc2w2Rdw9275cods
sOAyapo3Zag2kb3aqxaL8PccEclMyTmBuJ92RRVP
-----END CERTIFICATE-----
[root@rootca easy-rsa]# 

```

Copy the `ca.crt` from the RootCA machine to some other server, which is required to use this certificate to verify a local certificate (created later).


For RedHat based systems:
```
[root@rootca easy-rsa]# scp ~/easy-rsa/pki/ca.crt root@192.168.122.51:/etc/pki/ca-trust/source/anchors/
```
Then, on the target (RedHat) system, run `update-ca-trust` command:
```
[root@web-server ~]# ls -l /source/anchors/ 
total 4
-rw------- 1 root root 1200 Jul 15 23:09 ca.crt

[root@web-server ~]# update-ca-trust 
[root@web-server ~]# 
```

**Note:** As a result of above `update-ca-trust` command, the ca cert file `/etc/pki/ca-trust/source/anchors/ca.crt` is appended at the top of the `/etc/pki/tls/certs/ca-bundle.trust.crt` file. Verify this by doing a `head -3` on the file, as shown below:

```
[root@web-server ~]# head -3 /etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt
# rootca.example.com
-----BEGIN TRUSTED CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIJAKWOfHtXqWxfMA0GCSqGSIb3DQEBCwUAMB0xGzAZBgNV
[root@web-server ~]# 
```





For Debian based systems:
```
[root@rootca easy-rsa]# scp ~/easy-rsa/pki/ca.crt  root@192.168.122.52:/usr/local/share/ca-certificates/
```
Then, on the target (Debian) system, run `update-ca-certificates` command:
```
update-ca-certificates
```


Now your second Linux system will trust any certificate that has been signed by the CA server. 

We are not done yet!

The second Linux system - web-server - will lookup this CA for verification of the certificate chain, but the web-server does not have a certificate of it's own. It needs to create a Certificate Signing Request - CSR, and send it to RootCA, so it can be signed.

---

# The second Linux system - web-server:

You won't have `easyrsa` package on all the client computers / servers, though you will have OpenSSL. So we will use that.

## Create private key and CSR:

We will need to create a private key to sign the CSR. So, first we create this private key on our web server.

**Note:** The files are being created in the `/root/` directory. You can create them anywhere you want. The location needs to be a secure location, not under general public access. It can be `/etc/pki/tls/private/` for the private key.

```
[root@web-server ~]# openssl genrsa -out web-server.key
Generating RSA private key, 2048 bit long modulus
................+++
.................+++
e is 65537 (0x10001)
[root@web-server ~]# 
``` 

Now that you have a private key you can create a corresponding CSR, again using the openssl utility. You will be prompted to fill out a number of fields like Country, State, and City. You can enter a `.` if you’d like to leave a field blank.

Note: Be aware that if this were a real CSR, it is best to use the correct values for your location and organization.


Passphrase for CSR: D0ck3r

```
[root@web-server ~]# openssl req -new -key web-server.key -out web-server.csr
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [XX]:NO
State or Province Name (full name) []:Oslo
Locality Name (eg, city) [Default City]:Oslo
Organization Name (eg, company) [Default Company Ltd]:Exemplary Company
Organizational Unit Name (eg, section) []:IT
Common Name (eg, your name or your server's hostname) []:web-server.example.com
Email Address []:admin@example.com

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:D0ck3r
An optional company name []:Exemplary Company Pvt. Ltd.
[root@web-server ~]# 
```

Verify your CSR:

```
[root@web-server ~]# openssl req -in web-server.csr -noout -subject

subject=/C=NO/ST=Oslo/L=Oslo/O=Exemplary Company/OU=IT/CN=web-server.example.com/emailAddress=admin@example.com
[root@web-server ~]# 
```

Transport/copy this CSR from your web-server to the RootCA server, so it can be signed, and a certificate is obtained against it.

```
[root@web-server ~]# scp web-server.csr root@192.168.122.50:/tmp/
```

## Sign the CSR on the RootCA server:

Login to the RootCA server again. 

First, **import** the CSR sent by the web server:

```
[root@rootca easy-rsa]# easyrsa import-req /tmp/web-server.csr web-server.example.com 


WARNING: can't open config file: /root/easy-rsa/pki/safessl-easyrsa.cnf
WARNING: can't open config file: /root/easy-rsa/pki/safessl-easyrsa.cnf
Using SSL: openssl OpenSSL 1.0.2k-fips  26 Jan 2017

The request has been successfully imported with a short name of: web-server.example.com
You may now use this name to perform signing operations on this request.


[root@rootca easy-rsa]# 
```

Next, sign the CSR. Remember, the request type can either be one of `client`, `server`, or `ca`. Since we’re going to sign certificate for a fictional web-server, we will use the `server` request type:

When asked for the passphrase for `/root/easy-rsa/pki/private/ca.key` , type in "F3d0r@"

```
[root@rootca ~]# cd ~/easy-rsa/



[root@rootca easy-rsa]# easyrsa sign-req server web-server.example.com


WARNING: can't open config file: /root/easy-rsa/pki/safessl-easyrsa.cnf
WARNING: can't open config file: /root/easy-rsa/pki/safessl-easyrsa.cnf
WARNING: can't open config file: /root/easy-rsa/pki/safessl-easyrsa.cnf
Using SSL: openssl OpenSSL 1.0.2k-fips  26 Jan 2017
WARNING: can't open config file: /root/easy-rsa/pki/safessl-easyrsa.cnf
Unable to load config info from /root/easy-rsa/pki/safessl-easyrsa.cnf
WARNING: can't open config file: /root/easy-rsa/pki/safessl-easyrsa.cnf
Unable to load config info from /root/easy-rsa/pki/safessl-easyrsa.cnf


You are about to sign the following certificate.
Please check over the details shown below for accuracy. Note that this request
has not been cryptographically verified. Please be sure it came from a trusted
source or that you have verified the request checksum with the sender.

Request subject, to be signed as a server certificate for 825 days:

subject=
    countryName               = NO
    stateOrProvinceName       = Oslo
    localityName              = Oslo
    organizationName          = Exemplary Company
    organizationalUnitName    = IT
    commonName                = web-server.example.com
    emailAddress              = admin@example.com


Type the word 'yes' to continue, or any other input to abort.
  Confirm request details: yes
WARNING: can't open config file: /root/easy-rsa/pki/safessl-easyrsa.cnf
Unable to load config info from /root/easy-rsa/pki/safessl-easyrsa.cnf
WARNING: can't open config file: /root/easy-rsa/pki/safessl-easyrsa.cnf
WARNING: can't open config file: /root/easy-rsa/pki/safessl-easyrsa.cnf
Using configuration from /root/easy-rsa/pki/easy-rsa-9081.yl9zQv/tmp.U5dI7Z
Enter pass phrase for /root/easy-rsa/pki/private/ca.key:
Check that the request matches the signature
Signature ok
The Subject's Distinguished Name is as follows
countryName           :PRINTABLE:'NO'
stateOrProvinceName   :ASN.1 12:'Oslo'
localityName          :ASN.1 12:'Oslo'
organizationName      :ASN.1 12:'Exemplary Company'
organizationalUnitName:ASN.1 12:'IT'
commonName            :ASN.1 12:'web-server.example.com'
emailAddress          :IA5STRING:'admin@example.com'
Certificate is to be certified until Oct 18 21:58:19 2022 GMT (825 days)

Write out database with 1 new entries
Data Base Updated

Certificate created at: /root/easy-rsa/pki/issued/web-server.example.com.crt


[root@rootca easy-rsa]# 
```

Notice the certificate is created under `/root/easy-rsa/pki/issued/web-server.example.com.crt` , and is issued for 825 days.



With those steps complete, you have signed the web-server.csr CSR using the CA Server’s private key in `/root/easy-rsa/pki/private/ca.key`. The resulting web-server.crt file contains the web server’s public encryption key, as well as a new signature from the CA Server. The point of the signature is to tell anyone who trusts the CA that they can also trust the web-server certificate.

## Transport/copy the web-server.crt back to the web server:

```
[root@rootca easy-rsa]# scp /root/easy-rsa/pki/issued/web-server.example.com.crt root@192.168.122.51:/root/
```

On the web-server, check the files:

```
[root@web-server ~]# ls -ltrh
total 20K
-rw-------. 1 root root 1.3K Jul 15 14:34 anaconda-ks.cfg
-rw-r--r--  1 root root 1.7K Jul 15 23:39 web-server.key
-rw-r--r--  1 root root 1.2K Jul 15 23:40 web-server.csr
-rw-------  1 root root 4.8K Jul 16 00:07 web-server.example.com.crt
[root@web-server ~]# 
```


**Note:**  If you start apache at this point and access it using curl over HTTPS, the curl command will fail, citing certificate error. This will happen because we have not configured Apache to use correct certificates.


Copy the above files to certain locations on the file system, because we will configure Apache in the next step to use those files.

```
[root@web-server ~]# cp web-server.key /etc/pki/tls/private/
[root@web-server ~]# cp web-server.example.com.crt /etc/pki/tls/certs/
```


## Setup Apache on web-server and use the SSL certificate:


```
[root@web-server ~]# yum -y install httpd mod_ssl
```

Configure Apache with `ServerName` set to `web-server.example.com` . Configure it to use the various certificate files you have been creating in the previous steps.

Change the following:
* SSLCertificateFile    /etc/pki/tls/certs/localhost.crt
* SSLCertificateKeyFile /etc/pki/tls/private/localhost.key


  
To the following:
* SSLCertificateFile    /etc/pki/tls/certs/web-server.example.com.crt
* SSLCertificateKeyFile /etc/pki/tls/private/web-server.key

You can leave the directive `SSLCACertificateFile` as it is, or use a fixed location of the `ca.crt` file you obtained from the RootCA server. Remember, the file `/etc/pki/tls/certs/ca-bundle.crt` already has the `ca.crt` from RootCA server, because you ran the `update-ca-trust` program in the previous steps. 

* SSLCACertificateFile  /etc/pki/tls/certs/ca-bundle.crt

If you forgot to run that step, then simply use the exact path to the `ca.crt` file you obtained from the RootCA server.
* SSLCACertificateFile  /etc/pki/ca-trust/source/anchors/ca.crt


## Start the apache web service:

```
[root@web-server ~]# systemctl start httpd


[root@web-server ~]# systemctl status httpd
● httpd.service - The Apache HTTP Server
   Loaded: loaded (/usr/lib/systemd/system/httpd.service; disabled; vendor preset: disabled)
   Active: active (running) since Thu 2020-07-16 00:37:27 CEST; 15s ago
     Docs: man:httpd(8)
           man:apachectl(8)
 Main PID: 9533 (httpd)
   Status: "Total requests: 0; Current requests/sec: 0; Current traffic:   0 B/sec"
   CGroup: /system.slice/httpd.service
           ├─9533 /usr/sbin/httpd -DFOREGROUND
           ├─9534 /usr/sbin/httpd -DFOREGROUND
           ├─9535 /usr/sbin/httpd -DFOREGROUND
           ├─9536 /usr/sbin/httpd -DFOREGROUND
           ├─9537 /usr/sbin/httpd -DFOREGROUND
           └─9538 /usr/sbin/httpd -DFOREGROUND

Jul 16 00:37:27 web-server.example.com systemd[1]: Starting The Apache HTTP Server...
Jul 16 00:37:27 web-server.example.com systemd[1]: Started The Apache HTTP Server.
[root@web-server ~]# 
```

Since these two are test systemc, and dns is not in place, we will add entries for these two servers in `/etc/hosts` file.

```
[root@web-server ~]# cat /etc/hosts
127.0.0.1   localhost localhost.localdomain
192.168.122.51	web-server.example.com
192.168.122.50	rootca.example.com

[root@web-server ~]# 
```

```
[root@rootca easy-rsa]# cat /etc/hosts
127.0.0.1   localhost localhost.localdomain 
192.168.122.51  web-server.example.com
192.168.122.50  rootca.example.com

[root@rootca easy-rsa]# 
```

Also create a simple `index.html` file in `/var/www/html` directory. 

```
[root@web-server ~]# echo 'This is Apache Web Server!' > /var/www/html/index.html
```


## Verify setup using curl from both systems:

### HTTP:
```
[root@web-server ~]# curl http://web-server.example.com
This is Apache Web Server!
[root@web-server ~]# 
```

### HTTPS:
```
[root@web-server ~]# curl https://web-server.example.com
This is Apache Web Server!
[root@web-server ~]# 
```

It works without any SSL certificate errors!

We cannot check it from a browser, as the ca.crt file would need to be added to the browser manually. However, we can access this from another computer system, by specifying the path to the ca.crt file manually. 

Lets do this on the RootCA server.

### HTTP:
```
[root@rootca easy-rsa]# curl http://web-server.example.com
This is Apache Web Server!
```

### HTTPS:
```
[root@rootca easy-rsa]# curl https://web-server.example.com
curl: (60) Peer's Certificate issuer is not recognized.
More details here: http://curl.haxx.se/docs/sslcerts.html

curl performs SSL certificate verification by default, using a "bundle"
 of Certificate Authority (CA) public keys (CA certs). If the default
 bundle file isn't adequate, you can specify an alternate file
 using the --cacert option.
If this HTTPS server uses a certificate signed by a CA represented in
 the bundle, the certificate verification probably failed due to a
 problem with the certificate (it might be expired, or the name might
 not match the domain name in the URL).
If you'd like to turn off curl's verification of the certificate, use
 the -k (or --insecure) option.
[root@rootca easy-rsa]# 
```

What happened here? This is RootCA server, which is working as Root CA for our setup, using easyrsa tools. However, this system itself is not configured to use the `ca.crt` file it created earlier. That is what `curl` is complaining above - it cannot verify that this server is actually `web-server.example.com` or not, as it cannot verify that from "known" CAs.


To test this temporarily, we can simply pass the path to the CA file to our `curl` command.

```
[root@rootca easy-rsa]# curl --cacert /root/easy-rsa/pki/ca.crt   https://web-server.example.com
This is Apache Web Server!
[root@rootca easy-rsa]# 
```











---
# References: [https://www.digitalocean.com/community/tutorials/how-to-set-up-and-configure-a-certificate-authority-ca-on-debian-10](https://www.digitalocean.com/community/tutorials/how-to-set-up-and-configure-a-certificate-authority-ca-on-debian-10)
---

# Errors:


## Error 1:
```
[root@rootca easy-rsa]# easyrsa build-ca
WARNING: can't open config file: /root/easy-rsa/pki/safessl-easyrsa.cnf
WARNING: can't open config file: /root/easy-rsa/pki/safessl-easyrsa.cnf
Using SSL: openssl OpenSSL 1.0.2k-fips  26 Jan 2017

Easy-RSA error:

The OpenSSL config file cannot be found.
Expected location: /root/easy-rsa/pki/openssl-easyrsa.cnf

[root@rootca easy-rsa]# 
```


## Error 2:

```
[root@rootca easy-rsa]# easyrsa sign-req server web-server.example.com
WARNING: can't open config file: /root/easy-rsa/pki/safessl-easyrsa.cnf
WARNING: can't open config file: /root/easy-rsa/pki/safessl-easyrsa.cnf
WARNING: can't open config file: /root/easy-rsa/pki/safessl-easyrsa.cnf
Using SSL: openssl OpenSSL 1.0.2k-fips  26 Jan 2017

Easy-RSA error:

Unknown cert type 'server'

[root@rootca easy-rsa]#
```


Solution:
The easyrsa binary expects a x509-types directory where the binary is located.

```
[root@rootca easy-rsa]# cd /usr/local/bin/


[root@rootca bin]# ln -s /usr/share/easy-rsa/3/x509-types
```

This entire thing/process will be lot easier, if we simply perform all steps under `/usr/share/easyrsa` directory, instead of creating symlink mess.


