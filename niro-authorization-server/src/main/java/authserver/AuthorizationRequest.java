package authserver;

import java.util.Date;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.PrePersist;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
@Entity
public class AuthorizationRequest {
	private String clientId;
	private String clientSecret;
	private String redirectUri;
	private String grantType;
	private String code;
	
	@Id
	@GeneratedValue(strategy=GenerationType.AUTO)
	private Long id;
	private Date createdAt;

	@PrePersist
	void createdAt() {
		this.createdAt = new Date();
	}
}
