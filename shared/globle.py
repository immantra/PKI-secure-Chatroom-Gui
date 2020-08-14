signpattern="$signatures$"
deletpattern='deleteUser$$'
newpettern='newUser$$'
cryptpattern='$$crypt$$'
buffersize=5000000

ldaplogin="cn=admin,dc=suse,dc=com"
ldap_base='ou=users,dc=suse,dc=com'
ldap_password='Admin'


hostCS="localhost"
portCS=2025
connection_nb_CS=3

hostPKI="localhost"
portPKI=2128
connection_nb_PKI=3

def verify_cb(conn, cert, errnum, depth, ok):
    # This obviously has to be updated
    print ('Got certificate: %s' % cert.get_subject())
    return ok