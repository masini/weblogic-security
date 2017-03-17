connect('weblogic','weblog1c')
xacmlRoleMapper = cmo.getSecurityConfiguration().getDefaultRealm().lookupRoleMapper('XACMLRoleMapper')
xacmlRoleMapper.removeRole(None,'my-user')
xacmlRoleMapper.removeRole(None,'my-special-user')
