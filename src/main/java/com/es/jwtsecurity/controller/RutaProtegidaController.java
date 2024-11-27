package com.es.jwtsecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/ruta_protegida")
public class RutaProtegidaController {

    @GetMapping("/")
    public String rutaProtegida(Principal principal) {
        return "Hola "+principal.getName()+" esto es una ruta protegida";
    }
}
