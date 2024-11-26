package com.es.jwtsecurity.controller;

import com.es.jwtsecurity.dto.UsuarioLoginDTO;
import com.es.jwtsecurity.dto.UsuarioRegisterDTO;
import com.es.jwtsecurity.model.Usuario;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/usuarios")
public class UsuarioController {


    @PostMapping("/login")
    public String login(UsuarioLoginDTO usuarioLoginDTO) {
        return null;
    }


    @PostMapping("/register")
    public ResponseEntity<UsuarioRegisterDTO> register(UsuarioRegisterDTO usuarioRegisterDTO) {
        return null;
    }

}
