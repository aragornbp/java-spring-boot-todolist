package com.brunopaulin.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.brunopaulin.todolist.user.IUserRepository;

import at.favre.lib.crypto.bcrypt.BCrypt;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter{

  @Autowired
  private IUserRepository userRepository;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    //verifica qual a rota está passando
      var servletPath = request.getServletPath();
      System.out.println(servletPath);
      
      if(servletPath.startsWith("/tasks/")) {
        
        //pega a autenticação
        var authorization = request.getHeader("Authorization");

        var authEncoded = authorization.substring("Basic".length()).trim();

        byte[] authDecode = Base64.getDecoder().decode(authEncoded);

        var authString = new String(authDecode);

        System.out.println(authString);

        String[] credentials = authString.split(":");

        String username = credentials[0];
        String password = credentials[1];

        //validar usuário
        var user = this.userRepository.findByUsername(username);
        if (user == null) {
          response.sendError(401);
        }

        var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
        
        if (!passwordVerify.verified) {
          response.sendError(401);
        }
        
        request.setAttribute("idUser", user.getId());
        filterChain.doFilter(request, response);

      } else {
        System.out.println("saindo direto");
        filterChain.doFilter(request, response);
      }

    
    


  }

}
