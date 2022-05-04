package authserver;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class LoginRequest {
	private String username;
	private String password;
	private String reqid;
	private String state;
}
