package net.lucamasini.security;

import javax.ejb.EJB;
import javax.servlet.ServletException;
import javax.servlet.annotation.HttpConstraint;
import javax.servlet.annotation.ServletSecurity;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;

@WebServlet(name="MyWorkServlet", urlPatterns={"/myprotectedresource"})
@ServletSecurity(@HttpConstraint(rolesAllowed={"my-user"}))
public class MyProtectedServlet extends HttpServlet {

    @EJB
    private NoInterfaceBeanInWarModule service;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        Principal userPrincipal = req.getUserPrincipal();
        resp.getWriter().println(userPrincipal!=null?userPrincipal.getName():"anonymous");
        resp.getWriter().println("my-user: "+req.isUserInRole("my-user"));
        resp.getWriter().println("echo:"+service.echo("echo"));
    }
}
