package model.entity;

import jakarta.persistence.*;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@Data
@Entity
@Table(name="users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    @Column(unique = true, nullable = false)
    private String username;
    @Column(nullable = false)
    private String password;
    @ManyToOne(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @JoinColumn(name="role_id",referencedColumnName = "id")
    @Column(nullable = false)
    private Role role;

    public User(String username, String password, Collection<GrantedAuthority> authorities) {
        this.username = username;
        this.password = password;
        this.role = new Role();
        for (GrantedAuthority authority : authorities) {

        }
    }

    public User() {

    }
}
