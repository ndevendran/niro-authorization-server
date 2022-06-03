package authserver;

import java.util.List;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class LoginRequest {
	private String username;
	private String password;
	private String reqid;
	private String state;
	private String responseType;
	private List<String> scopes;
}
