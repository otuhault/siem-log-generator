ES 8.5
New AQ API endpoints that allows searches to be run as an admin.
Enable execute_es_permitted_searches_as_admin feature flag in mc_search.conf file.
When ON, searches run as the system token -> RBAC is enforced via stored queue metadata instead.
When OFF (default): searches run as the user -> user's permissions apply

