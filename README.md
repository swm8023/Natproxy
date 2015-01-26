# Natproxy
Implenment port forwarding by dual proxys.

# Example
Config file
```
<natproxy>
    <server-addr>123.123.123.123</server-addr>
    <server-port>8888</server-port>
    <port-mappings>
        <mapping>
            <client-addr>192.168.0.126</client-addr>
            <client-port>3389</client-port>
            <mapping-port>8881</mapping-port>
        </mapping>
        <mapping>
            <client-addr>192.168.0.116</client-addr>
            <client-port>80</client-port>
            <mapping-port>8882</mapping-port>
        </mapping>
    </port-mappings>
</natproxy>
```
  
Compile with cmake in the diretory 'build'
```
mkdir build && cd build
cmake ..
make
```
  
Run server at 123.123.123.123
```
./bin/npserver ../config.xml
```
  
Run Client at local network
```
./bin/npclient ../config.xml
```
  
Then you can access 192.168.0.126:3389 by 123.123.123.123:8881 and access 192.168.0.116:80 by 123.123.123.123:8882.  
   
This Project is depend on libohnet.
