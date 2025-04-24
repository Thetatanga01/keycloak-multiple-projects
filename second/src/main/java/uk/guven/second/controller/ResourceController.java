package uk.guven.second.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import uk.guven.second.model.Resource;
import uk.guven.second.service.ResourceService;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/resources")
public class ResourceController {

    private final ResourceService resourceService;

    public ResourceController(ResourceService resourceService) {
        this.resourceService = resourceService;
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('user')")
    public ResponseEntity<List<Resource>> getAllResources() {
        return ResponseEntity.ok(resourceService.getAllResources());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('user')")
    public ResponseEntity<Object> getResourceById(@PathVariable String id) {
        Resource resource = resourceService.getResourceById(id);

        if (resource == null) {
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Kaynak bulunamadı: " + id);
            response.put("status", "error");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
        }

        return ResponseEntity.ok(resource);
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('admin')")
    public ResponseEntity<Resource> createResource(@RequestBody Resource resource, @AuthenticationPrincipal Jwt jwt) {
        String username = jwt.getClaimAsString("preferred_username");
        Resource createdResource = resourceService.createResource(resource, username);
        return ResponseEntity.status(HttpStatus.CREATED).body(createdResource);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyRole('admin')")
    public ResponseEntity<Object> updateResource(
        @PathVariable String id,
        @RequestBody Resource resource,
        @AuthenticationPrincipal Jwt jwt) {

        String username = jwt.getClaimAsString("preferred_username");
        Resource updatedResource = resourceService.updateResource(id, resource, username);

        if (updatedResource == null) {
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Kaynak bulunamadı: " + id);
            response.put("status", "error");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
        }

        return ResponseEntity.ok(updatedResource);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyRole('admin')")
    public ResponseEntity<Object> deleteResource(@PathVariable String id) {
        boolean deleted = resourceService.deleteResource(id);

        if (!deleted) {
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Kaynak bulunamadı: " + id);
            response.put("status", "error");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
        }

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Kaynak başarıyla silindi: " + id);
        response.put("status", "success");
        return ResponseEntity.ok(response);
    }
}
