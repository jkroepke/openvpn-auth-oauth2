# Filesystem Permissions

When started by systemd, openvpn runs with a [dynamic arbitrary UID](https://0pointer.net/blog/dynamic-users-with-systemd.html).
This means that it may not have access to certain files and directories if the appropriate permissions are not set.

Any additional files, such as TLS keys, should reside in the `/etc/openvpn-auth-oauth2/` directory.
The ownership of these files should be set to `root`, and the group should be set to `openvpn-auth-oauth2`.
This setup ensures that openvpn has the necessary permissions to access and utilize these files.

When installing the openvpn-auth-oauth2 Linux package, the system automatically creates the openvpn-auth-oauth2 group.
This group manages access to the necessary files and directories
and should be used to control the permissions of any additional files.
