package ch.bbw.owasp.web;

import ch.bbw.owasp.file.FileEntity;
import ch.bbw.owasp.file.FileService;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

@Controller
public class FileController {

    private final FileService fileService;

    public FileController(FileService fileService) {
        this.fileService = fileService;
    }

    @GetMapping("/files")
    public String list(Authentication auth, Model model) {
        model.addAttribute("files", fileService.listOwn(auth.getName()));
        return "files";
    }

    @PostMapping("/files/upload")
    public String upload(@RequestParam("file") MultipartFile file,
                         Authentication auth,
                         RedirectAttributes redirect) {
        try {
            FileEntity saved = fileService.store(file, auth.getName());
            redirect.addFlashAttribute("message",
                    "Uploaded " + saved.getOriginalName() + " (sha256 " + saved.getSha256() + ")");
        } catch (IllegalArgumentException e) {
            redirect.addFlashAttribute("error", e.getMessage());
        }
        return "redirect:/files";
    }

    @GetMapping("/files/{id}/download")
    public ResponseEntity<ByteArrayResource> download(@PathVariable Long id, Authentication auth) {
        boolean isAdmin = auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));

        FileService.FileDownload dl = fileService.load(id, auth.getName(), isAdmin);

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"" + dl.filename() + "\"")
                .contentType(MediaType.parseMediaType(dl.contentType()))
                .body(new ByteArrayResource(dl.bytes()));
    }

    /**
     * A01 method-level security demo: even though the URL is also gated to
     * /admin/** in SecurityConfig, @PreAuthorize enforces the role at the
     * method boundary — defence in depth.
     */
    @GetMapping("/admin/files")
    @PreAuthorize("hasRole('ADMIN')")
    @ResponseBody
    public List<String> allFiles() {
        return fileService.listAll().stream().map(FileEntity::getOriginalName).toList();
    }
}
