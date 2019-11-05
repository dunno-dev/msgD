# msgD
Small python direct messenger example with encoding <br>
File descriptions: <br>
  -- msg.conf (it is server config. We suggest leave port as is) <br>
  -- client.py (client executable. Usage: python3 client.py <ip> [opt:port]. Default port is 4096) <br>
  -- server.py (server executable. Usage: python3 server.py) <br>
***Note:*** If you want to connect over WAN you must forward port. It is not a bug because it is *DIRECT* messenger. <br>
If you want to send a file, type FILETYPE in client. (very bugged)<br>Server can only read messages. Server feature to send them will be added.<br>
P. S. It is only example, not enterprice edition or big open-source project.<br>
Requirments: <br>
  --pyaes<br>
  --pbkdf2<br>
  (install it by executing: pip install -r requirments.txt)
