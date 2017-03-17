package net.lucamasini.security;

import javax.ejb.Stateless;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;

@Path("/myresource")
@Stateless
public class MySimpleNoInterfaceBean {
    @GET
    public String echo(@QueryParam("input") String input) {
        return "$"+input+"$";
    }
}
