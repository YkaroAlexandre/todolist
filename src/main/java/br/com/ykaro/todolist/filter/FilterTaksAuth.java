package br.com.ykaro.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.ykaro.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


// Classe para autenticação do usuário.
@Component
public class FilterTaksAuth extends OncePerRequestFilter{

    @Autowired
    private IUserRepository userRepository;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {


            var servletPath = request.getServletPath();

            // Validadndo se a rota é na aba de tasks.
            if(servletPath.startsWith("/tasks/")){

                // 1- Pegar autenticação(usuário e senha);
                var authorization = request.getHeader("Authorization");
                    // Retirando palavra "Basic" e após isso, retirando os espaços que estão sobrando.
                var authEncoded = authorization.substring("Basic".length()).trim();

                byte[] authDecoded = Base64.getDecoder().decode(authEncoded);
                var authString = new String(authDecoded);
                
                String[] credentials = authString.split(":");
                String username = credentials[0];
                String password = credentials[1];
                
                // 2 - Validar usuário;

                var user = this.userRepository.findByUsername(username);
                if(user == null){
                    response.sendError(401);
                }else{
                    // 3 - Validar senha;
                    var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                    if(passwordVerify.verified){

                        request.setAttribute("idUser",user.getID());

                        filterChain.doFilter(request, response);

                    }else{
                        response.sendError(401);
                    }
                    
                    // 4 - Seguir
                }
            }else{
                filterChain.doFilter(request, response);

            }

           
            
    }

    

}
