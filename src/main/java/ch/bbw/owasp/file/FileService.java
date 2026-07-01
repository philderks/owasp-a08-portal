package ch.bbw.owasp.file;

import ch.bbw.owasp.security.SecurityAuditLogger;
import jakarta.annotation.PostConstruct;
import org.apache.tika.Tika;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

@Service
public class FileService {

    // Defensive deny-list on top of the MIME allow-list (A08).
    private static final List<String> FORBIDDEN_EXTENSIONS =
            List.of(".exe", ".sh", ".bat", ".cmd", ".js", ".jar", ".php", ".bin");

    private final FileRepository repository;
    private final SecurityAuditLogger audit;
    private final Tika tika = new Tika();

    private final Path storageDir;
    private final List<String> allowedMimeTypes;

    public FileService(FileRepository repository,
                       SecurityAuditLogger audit,
                       @Value("${app.storage-dir}") String storageDir,
                       @Value("${app.allowed-mime-types}") List<String> allowedMimeTypes) {
        this.repository = repository;
        this.audit = audit;
        this.storageDir = Paths.get(storageDir).toAbsolutePath().normalize();
        this.allowedMimeTypes = allowedMimeTypes;
    }

    @PostConstruct
    void init() throws IOException {
        Files.createDirectories(storageDir);
    }

    /** A08: validate by content, hash, then persist. */
    public FileEntity store(MultipartFile file, String owner) {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("Empty upload");
        }
        byte[] bytes = readBytes(file);

        // 1) Content-based type detection — IGNORE the client-supplied Content-Type.
        String detected = tika.detect(bytes);
        if (!allowedMimeTypes.contains(detected)) {
            throw new IllegalArgumentException("File type not allowed: " + detected);
        }

        // 2) Reject disguised executables by name as a second barrier.
        String name = sanitize(file.getOriginalFilename());
        String lower = name.toLowerCase(Locale.ROOT);
        if (FORBIDDEN_EXTENSIONS.stream().anyMatch(lower::endsWith)) {
            throw new IllegalArgumentException("Executable upload rejected: " + name);
        }

        // 3) Integrity anchor.
        String sha256 = sha256(bytes);

        // 4) Store the blob under a random name (no path traversal via filename).
        String storedName = UUID.randomUUID().toString();
        Path target = storageDir.resolve(storedName).normalize();
        if (!target.startsWith(storageDir)) {
            throw new IllegalArgumentException("Path traversal detected");
        }
        try {
            Files.write(target, bytes);
        } catch (IOException e) {
            throw new IllegalStateException("Could not store file", e);
        }

        FileEntity saved = repository.save(new FileEntity(
                owner, name, detected, sha256, target.toString(), bytes.length));
        audit.fileUploaded(owner, saved.getId(), sha256);
        return saved;
    }

    /**
     * A01 ownership check + A08 integrity verification on read.
     * Throws AccessDeniedException (403) or IntegrityException (500) — both are
     * logged so the events show up in the audit trail.
     */
    public FileDownload load(Long id, String requester, boolean isAdmin) {
        FileEntity entity = repository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("No such file"));

        if (!entity.getOwner().equals(requester) && !isAdmin) {
            audit.accessDenied(requester, id);
            throw new AccessDeniedException("Not your file");
        }

        byte[] bytes;
        try {
            bytes = Files.readAllBytes(Paths.get(entity.getStoredPath()));
        } catch (IOException e) {
            throw new IllegalStateException("Could not read file", e);
        }

        String actual = sha256(bytes);
        if (!actual.equals(entity.getSha256())) {
            audit.integrityViolation(id, entity.getSha256(), actual);
            throw new IntegrityException("File integrity check failed for id=" + id);
        }

        audit.fileDownloaded(requester, id);
        return new FileDownload(entity.getOriginalName(), entity.getContentType(), bytes);
    }

    public List<FileEntity> listOwn(String owner) {
        return repository.findByOwner(owner);
    }

    /** A01: only reachable via the ADMIN-gated /admin/files endpoint. */
    public List<FileEntity> listAll() {
        return repository.findAll();
    }

    // --- helpers ---------------------------------------------------------

    private byte[] readBytes(MultipartFile file) {
        try {
            return file.getBytes();
        } catch (IOException e) {
            throw new IllegalStateException("Could not read upload", e);
        }
    }

    private String sha256(byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** Strip any directory components a malicious client might send. */
    private String sanitize(String filename) {
        if (filename == null || filename.isBlank()) {
            return "upload";
        }
        return Paths.get(filename).getFileName().toString();
    }

    public record FileDownload(String filename, String contentType, byte[] bytes) {
    }
}
