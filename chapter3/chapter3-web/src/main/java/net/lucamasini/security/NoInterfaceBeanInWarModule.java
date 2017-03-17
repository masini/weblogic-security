package net.lucamasini.security;

import javax.annotation.security.DeclareRoles;
import javax.annotation.security.RolesAllowed;
import javax.annotation.security.RunAs;
import javax.ejb.Stateless;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;

@Stateless
@DeclareRoles({"my-user", "my-special-user"})
@RunAs("my-special-user")
public class NoInterfaceBeanInWarModule {
    @RolesAllowed("my-special-user")
    public String echo(@QueryParam("input") String input) {
        return "$"+input+"$";
    }
}
