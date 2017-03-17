<%@ page contentType="text/plain;charset=UTF-8" language="java" %><%
    if( "testuser".equals(request.getParameter("username")) && "testpassword".equals(request.getParameter("password"))) {
        response.setStatus(200);
    } else {
        response.setStatus(401);
    }
%>