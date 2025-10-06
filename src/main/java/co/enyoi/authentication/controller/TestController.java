package co.enyoi.authentication.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1")
public class TestController {


    @GetMapping
    public Map<String, String> health(HttpServletRequest request) {
        System.out.println(request.getHeader("X-Username"));
        return Map.of("status", "ok");
    }

    @GetMapping("/private/health")
    public Map<String, String> healthPrivate(){
        return Map.of("status", "ok", "message", "private endpoint");

    }

    @GetMapping("/private/admin/health")
    //@PreAuthorize("hasRole('ADMIN')")
    public Map<String, String> healthPrivateAdmin(){
        return Map.of("status", "ok", "message", "private admin endpoint");
    }

    @GetMapping("/private/admin/write/health")
    //@PreAuthorize("hasAuthority('WRITE')")
    public Map<String, String> healthAdminWrite(){
        return Map.of("status", "ok", "message", "private endpoint  write permission");
    }
}
