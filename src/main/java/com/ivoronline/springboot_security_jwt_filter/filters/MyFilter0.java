package com.ivoronline.springboot_security_jwt_filter.filters;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

@Order(0)
@Component
public class MyFilter0 implements Filter {

  //==================================================================
  // DO FILTER
  //==================================================================
  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
    throws IOException, ServletException
  {
    try {
      chain.doFilter(request, response);
    }
    catch (Exception exception) {
      exception.printStackTrace();
      response.getWriter().write(exception.getMessage());
    }
  }

}

