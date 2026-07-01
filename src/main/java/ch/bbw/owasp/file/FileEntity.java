package ch.bbw.owasp.file;

import jakarta.persistence.*;

@Entity
@Table(name = "stored_file")
public class FileEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String owner;          // username of the uploader

    @Column(nullable = false)
    private String originalName;

    @Column(nullable = false)
    private String contentType;    // content-detected, NOT the client header

    // A08: integrity anchor. Recomputed on every download and compared.
    @Column(nullable = false, length = 64)
    private String sha256;

    @Column(nullable = false)
    private String storedPath;

    @Column(nullable = false)
    private long sizeBytes;

    protected FileEntity() {
    }

    public FileEntity(String owner, String originalName, String contentType,
                      String sha256, String storedPath, long sizeBytes) {
        this.owner = owner;
        this.originalName = originalName;
        this.contentType = contentType;
        this.sha256 = sha256;
        this.storedPath = storedPath;
        this.sizeBytes = sizeBytes;
    }

    public Long getId() { return id; }
    public String getOwner() { return owner; }
    public String getOriginalName() { return originalName; }
    public String getContentType() { return contentType; }
    public String getSha256() { return sha256; }
    public String getStoredPath() { return storedPath; }
    public long getSizeBytes() { return sizeBytes; }
}
