package uk.guven.first.service;

import org.springframework.stereotype.Service;
import uk.guven.first.model.Resource;

import java.util.*;

@Service
public class ResourceService {

    private final Map<String, Resource> resources = new HashMap<>();

    // Bazı örnek veriler ekleyelim
    public ResourceService() {
        Resource resource1 = new Resource(
            UUID.randomUUID().toString(),
            "Örnek Kaynak 1",
            "Bu bir örnek kaynaktır",
            "system"
        );
        Resource resource2 = new Resource(
            UUID.randomUUID().toString(),
            "Örnek Kaynak 2",
            "Bu başka bir örnek kaynaktır",
            "system"
        );

        resources.put(resource1.getId(), resource1);
        resources.put(resource2.getId(), resource2);
    }

    public List<Resource> getAllResources() {
        return new ArrayList<>(resources.values());
    }

    public Resource getResourceById(String id) {
        return resources.get(id);
    }

    public Resource createResource(Resource resource, String username) {
        String id = UUID.randomUUID().toString();
        resource.setId(id);
        resource.setCreatedBy(username);
        resources.put(id, resource);
        return resource;
    }

    public Resource updateResource(String id, Resource resource, String username) {
        if (!resources.containsKey(id)) {
            return null;
        }

        Resource existingResource = resources.get(id);
        existingResource.setName(resource.getName());
        existingResource.setDescription(resource.getDescription());

        return existingResource;
    }

    public boolean deleteResource(String id) {
        if (!resources.containsKey(id)) {
            return false;
        }

        resources.remove(id);
        return true;
    }
}
