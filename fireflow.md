# reconflow — reporte de 10.129.244.214
*Generado: 2026-10-31T02:39:15.664518+00:00*

## Puertos abiertos

| Puerto | Servicio | Versión |
|---|---|---|
| 22/tcp | ssh | OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 Ubuntu Linux; protocol 2.0 |
| 443/tcp | http | nginx |

## Enumeración

### Puerto 22
- **[sugerido]** `nmap -p22 --script ssh2-enum-algos,ssh-auth-methods 10.129.244.214`  
  _Algoritmos y métodos de autenticación_

### Puerto 443
- **[ejecutado]** `whatweb -a3 http://10.129.244.214:443`  
  _Fingerprint de tecnologías web_

```
[1m[34mhttp://10.129.244.214:443[0m [400 Bad Request] [1mCountry[0m[[0m[22mRESERVED[0m][[1m[31mZZ[0m], [1mHTTPServer[0m[[1m[36mnginx[0m], [1mIP[0m[[0m[22m10.129.244.214[0m], [1mTitle[0m[[1m[33m400 The plain HTTP request was sent to HTTPS port[0m], [1mnginx[0m
```
- **[ejecutado]** `curl -sI http://10.129.244.214:443`  
  _Cabeceras HTTP_

```
HTTP/1.1 400 Bad Request
Server: nginx
Date: Sat, 31 Oct 2026 02:39:15 GMT
Content-Type: text/html
Content-Length: 248
Connection: close
```
- **[sugerido]** `feroxbuster -u http://10.129.244.214:443 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt`  
  _Fuzzing de directorios_
- **[sugerido]** `nikto -h http://10.129.244.214:443`  
  _Escaneo de vulnerabilidades web (ruidoso)_
