# TestHttp

### Program description

Testhttp_raw tests given http(s) address. It sends HTTP GET request with cookies specified in file. <br> In case of response 200 OK prints
cookies sent by server and content length. Otherwise prints response status. <br>
Testhttp enables testing https websites. To send encoded data if tested website is https, it will create
tunnel using stunnel. 

### Installation

```
git clone
make
```

### Usage

```
./testhttp <cookies file> <tested http address>
```

Tests given http(s) address. In HTTP GET request set all cookies from file.
File format is: <br>
Each cookie is described by single line in format: cookiekey=cookievalue

```
./testhttp_raw <host address>:<host port> <cookies file> <tested http address>
```

Connects to specified host address and port, then requests tested http address.
GET request includes all cookies from cookie file. Cookie file format is expected as above. <br>
<br>
If you only want to test http(s) website, I'll strongly suggest to use <b>testhttp</b> program.