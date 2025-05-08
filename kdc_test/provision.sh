#!/bin/bash

set -xuo pipefail

ln -s /usr/lib64/krb5/plugins/kdb/db2.so /usr/lib64/krb5/plugins/kdb/db2

yes master_password | kdb5_util create -s
yes admin_password | kadmin.local -q "addprinc root/admin"
yes a-secure-password | kadmin.local -q "addprinc +requires_preauth testuser"
yes a-secure-password | kadmin.local -q "addprinc testuser1"
yes a-secure-password | kadmin.local -q "addprinc testuser2"
yes a-secure-password | kadmin.local -q "addprinc testuser3"
yes a-secure-password | kadmin.local -q "addprinc testuser_no_preauth"

yes a-secure-password | kadmin.local -q "addprinc -policy hosts host/localhost"
yes a-secure-password | kadmin.local -q "addprinc -policy hosts cifs/opensuse.example.com"

kadmin.local -q "addprinc -randkey -policy hosts host/pepper.example.com"
kadmin.local -q "addprinc -randkey -policy hosts host/spot.example.com"

# Extract all keys to the keytab, useful for decrypt in wireshark
kadmin.local -q "ktadd -norandkey krbtgt/EXAMPLE.COM@EXAMPLE.COM"
kadmin.local -q "ktadd -norandkey testuser@EXAMPLE.COM"
kadmin.local -q "ktadd -norandkey testuser_preauth@EXAMPLE.COM"
kadmin.local -q "ktadd -norandkey host/pepper.example.com@EXAMPLE.COM"
kadmin.local -q "ktadd -norandkey host/spot.example.com@EXAMPLE.COM"
kadmin.local -q "ktadd -norandkey host/localhost@EXAMPLE.COM"
kadmin.local -q "ktadd -norandkey cifs/opensuse.example.com@EXAMPLE.COM"
