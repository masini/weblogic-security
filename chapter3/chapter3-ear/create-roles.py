connect('weblogic','weblog1c')
xacmlRoleMapper = cmo.getSecurityConfiguration().getDefaultRealm().lookupRoleMapper('XACMLRoleMapper')
xacmlRoleMapper.createRole(None,'my-user',None)
xacmlRoleMapper.setRoleExpression(None,'my-user', 'Grp(users)')
xacmlRoleMapper.createRole(None,'my-special-user',None)
xacmlRoleMapper.setRoleExpression(None,'my-special-user', 'Grp(users)')