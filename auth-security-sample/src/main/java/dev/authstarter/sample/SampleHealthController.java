package dev.authstarter.sample;

import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SampleHealthController {

    @GetMapping("/api/sample/health")
    Map<String, String> health() {
        return Map.of("status", "ok");
    }
}
