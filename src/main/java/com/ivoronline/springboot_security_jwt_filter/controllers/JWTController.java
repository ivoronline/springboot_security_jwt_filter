package com.ivoronline.springboot_security_jwt_filter.controllers;

import com.ivoronline.springboot_security_jwt_filter.utils.JWTUtil;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.io.IOException;

@RestController
public class JWTController {

  //PROPERTIES
  @Autowired JWTUtil               jwtUtil;
  @Autowired AuthenticationManager authenticationManager;

  //==================================================================
  // CREATE JWT
  //==================================================================
  // http://localhost:8080/CreateJWT?username=myuser&password=myuserpassword
  // eyJhbGciOiJIUzI1NiJ9.eyJhdXRob3JpdGllcyI6IltST0xFX0FETUlOLCBST0xFX1VTRVJdIiwidXNlcm5hbWUiOiJteXVzZXIifQ.MshnOBSYy6575qA2RBT4bisjIGmsuEUVNQtLnm-QSv8
  @RequestMapping("CreateJWT")
  String createJWT(@RequestParam String username, @RequestParam String password) throws IOException {

    //AUTHENTICATE (COMPARE ENTERED AND STORED CREDENTIALS)
    Authentication authentication  = new UsernamePasswordAuthenticationToken(username, password);
                   authentication = authenticationManager.authenticate(authentication); //Exception

    //CREATE JWT
    String authorities = authentication.getAuthorities().toString(); //"[ROLE_ADMIN, ROLE_USER]"
    String jwt         = jwtUtil.createJWT(username, authorities);

    //RETURN JWT
    return jwt;

  }

  //==================================================================
  // GET CLAIMS
  //==================================================================
  // http://localhost:8080/GetClaims?jwt=eyJhbGciOiJIUzI1NiJ9.eyJhdXRob3JpdGllcyI6IltST0xFX0FETUlOLCBST0xFX1VTRVJdIiwidXNlcm5hbWUiOiJteXVzZXIifQ.MshnOBSYy6575qA2RBT4bisjIGmsuEUVNQtLnm-QSv8
  // authorization:Bearer <JWT>
  // {"authorities":"[ROLE_ADMIN, ROLE_USER]","username":"myuser"}
  @RequestMapping("GetClaims")
  Claims getClaims(
    @RequestParam (required = false) String jwt,
    @RequestHeader(required = false) String authorization
  ) throws Exception {

    //FOR AUTHORIZATION HEADER
    if(authorization!=null) { jwt = jwtUtil.getJWTFromAuthorizationHeader(authorization); }

    //GET CLAIMS
    Claims claims = jwtUtil.getClaims(jwt);

    //RETURN CLAIMS
    return claims;

  }

  //==================================================================
  // EXCEPTION HANDLER                             (For all Endpoints)
  //==================================================================
  @ExceptionHandler
  String exceptionHandler(Exception exception) {
    return exception.getMessage(); //Bad credentials
  }

}
