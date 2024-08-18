# HTTPS Listener

> [!IMPORTANT]
> Remember to set `CONFIG_HTTP_BASEURL` correctly. It should start with `https://` following your public domain name plus port.

Some SSO Provider like Entra ID requires `https://` based redirect URL.
In the default configuration, openvpn-auth-oauth2 listen on `http://`.
There are two common ways to set up an HTTPS listener

### Reverse proxy (nginx, traefik)

You can use one of your favorite http reverse proxies.
Configure HTTPS on reverse proxy and proxy to an HTTP instance of openvpn-auth-oauth2.
For beginners, [traefik](https://traefik.io/traefik/) is recommended since it [natively](https://doc.traefik.io/traefik/https/acme/)
supports [Let's Encrypt](https://letsencrypt.org/) where you can get public SSL certificates for free.

### Using native HTTPS support

openvpn-auth-oauth2 supports HTTPS out of the box.
If openvpn-auth-oauth2 runs as systemd service, the HTTPS certificates must place in `/etc/openvpn-auth-oauth2/` with
the owner `root` and the group `openvpn-auth-oauth2`. See [Filesystem Permissions](Filesystem%20Permissions) for more information.

<table>
<thead><tr><td>env/sysconfig configuration</td></tr></thead>
<tbody><tr><td>

```ini
CONFIG_HTTP_TLS=true
CONFIG_HTTP_KEY=/etc/openvpn-auth-oauth2/server.key
CONFIG_HTTP_CERT=/etc/openvpn-auth-oauth2/server.crt
```
</td></tr></tbody>
<thead><tr><td>yaml configuration</td></tr></thead>
<tbody><tr><td>

```yaml
http:
  tls: true
  key: /etc/openvpn-auth-oauth2/server.key
  cert: /etc/openvpn-auth-oauth2/server.crt
```
</td></tr></tbody>
</table>

To set up a self-signed certificate, you can use the command below:

```bash
export DOMAIN_NAME=vpn.example.com
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout /etc/openvpn-auth-oauth2/server.key \
  -out /etc/openvpn-auth-oauth2/server.crt \
  -subj "/CN=$DOMAIN_NAME" -addext "subjectAltName=DNS:$DOMAIN_NAME"
chown root:openvpn-auth-oauth2 /etc/openvpn-auth-oauth2/server.key /etc/openvpn-auth-oauth2/server.crt
chmod 640 /etc/openvpn-auth-oauth2/server.key /etc/openvpn-auth-oauth2/server.crt
```

You can also use [Let's Encrypt](https://letsencrypt.org/) to get public SSL certificates for free.
The [certbot](https://certbot.eff.org/instructions) is a recommended tool to get SSL certificates.
Alternatively, can use [acme.sh](https://acme.sh/), which is a pure Unix shell script implementing ACME client protocol.

openvpn-auth-oauth2 requires a [`SIGHUP` signal](https://en.wikipedia.org/wiki/SIGHUP) to reload the TLS certificate.

If you are using certbot, please drop some instructions to setup it.

#### Run HTTPS listener on 443 port

Running openvpn-auth-oauth2 on port 443 requires special permissions.

Create a new file `/etc/systemd/system/openvpn-auth-oauth2.service.d/override.conf` with the following content:

```ini
[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
PrivateUsers=false
```

Then, run the following commands:

```bash
echo "capability net_bind_service," > /etc/apparmor.d/local/usr.bin.openvpn-auth-oauth2
systemctl restart apparmor
systemctl daemon-reload
systemctl restart openvpn-auth-oauth2
```
