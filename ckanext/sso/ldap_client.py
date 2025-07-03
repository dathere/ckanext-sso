import logging
from ldap3 import Server, Connection, ALL, SUBTREE, ALL_ATTRIBUTES
import ckan.plugins.toolkit as tk

log = logging.getLogger(__name__)



def build_ldap_connection(server_address, username, password):
        """Builds and returns an LDAP connection."""
        server = Server(server_address, get_info=ALL)
        conn = Connection(server, user=username, password=password, auto_bind=True)
        return conn

class LDAPClient(object):
    def __init__(self):
        self.server_address = tk.config.get("ckanext.sso.ldap_server")
        self.ldap_base_dn = tk.config.get("ckanext.sso.ldap_base_dn")
        self.ldap_user = tk.config.get("ckanext.sso.ldap_user")
        self.ldap_pass = tk.config.get("ckanext.sso.ldap_pass")
        self.conn = build_ldap_connection(self.server_address,self.ldap_user,self.ldap_pass)
        if not self.conn.bound:
            raise Exception("LDAP Connection could not be established")
        else:
            log.debug(f"LDAP connection established")
            

    def query_user_by_email(self, email):
        """Queries LDAP for a user based on their email address."""
        search_filter = f'(&(objectClass=Person)(mail={email}))'    
        self.conn.search(self.ldap_base_dn, search_filter, SUBTREE, attributes=ALL_ATTRIBUTES)

        # Print the results
        if self.conn.entries:
            return self.conn.entries[0].entry_attributes_as_dict  # Return the first matching group
    
    def get_distinct_departments(self):
        """Fetches all distinct department values from all user entries in the LDAP."""
        search_filter = '(objectClass=Person)'  # Adjust this filter based on your LDAP schema
        attributes = ['department','departmentNumber']

        self.conn.search(self.ldap_base_dn, search_filter, SUBTREE, attributes=attributes)

        departments = {}

        # Collect distinct department values
        for entry in self.conn.entries:
            department = entry.department.value if 'department' in entry else None
            if department:  # Only add non-empty departments
                #departments[department]=get_group_by_display_name(conn,base_dn,department)
                departments[department]=entry.departmentNumber.value
        return departments

